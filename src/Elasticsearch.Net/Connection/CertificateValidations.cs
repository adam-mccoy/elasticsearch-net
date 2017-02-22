using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Elasticsearch.Net
{
	/// <summary>
	/// A collection of handy baked in server certificate validation callbacks
	/// </summary>
	public static class CertificateValidations
	{
		/// <summary>
		/// DANGEROUS, never use this in production validates ALL certificates to true.
		/// </summary>
		/// <returns>Always true, allowing ALL certificates</returns>
		public static bool AllowAll(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) => true;

		/// <summary>
		/// Always false, in effect blocking ALL certificates
		/// </summary>
		/// <returns>Always false, always blocking ALL certificates</returns>
		public static bool DenyAll(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) => false;

		private static readonly ConcurrentDictionary<string, bool> _knownPrints = new ConcurrentDictionary<string, bool>();

		/// <summary>
		/// Helper to create a certificate validation callback based on the certificate authority certificate that we used to
		/// generate the nodes certificates with.
		/// </summary>
		/// <param name="caCertificate">The ca certificate used to generate the nodes certificate </param>
		/// <param name="trustRoot">Custom CA are never trusted by default unless they are in the machines trusted store, set this to true
		/// if you've added the CA to the machines trusted store. In which case UntrustedRoot should not be accepted.
		/// </param>
		/// <param name="revocationMode">By default we do not check revocation, it is however recommended to check this (either offline or online).</param>
		/// <returns></returns>
		public static Func<object, X509Certificate, X509Chain, SslPolicyErrors, bool> Authority(
			X509Certificate caCertificate, bool trustRoot = true, X509RevocationMode revocationMode = X509RevocationMode.NoCheck) =>
			(sender, cert, chain, errors) => CustomCaCallback(caCertificate, cert, chain, errors, trustRoot, revocationMode);

		private static bool CustomCaCallback(X509Certificate ca, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors, bool trustRoot, X509RevocationMode revocationMode)
		{
			if (errors == SslPolicyErrors.None) return true;

			var certificateHash = certificate.GetCertHashString();
			if (certificateHash == null) return false;
			bool knownThumbprintIsValid;
			if (_knownPrints.TryGetValue(certificateHash, out knownThumbprintIsValid))
				return knownThumbprintIsValid;

			var isValid = IsValidCertificate(new X509Certificate2(ca),  certificate, chain, trustRoot, revocationMode);
			_knownPrints.AddOrUpdate(certificateHash, isValid, (s, b) => isValid);
			return isValid;
		}
		private static bool IsValidCertificate(X509Certificate2 caCertificate, X509Certificate certificate, X509Chain chain, bool trustRoot, X509RevocationMode revocationMode)
		{
			var privateChain = new X509Chain {ChainPolicy = {RevocationMode = revocationMode}};
			privateChain.ChainPolicy.ExtraStore.Add(caCertificate);
			privateChain.Build(new X509Certificate2(certificate));

			//Assert our chain has the same number of elements as the certifcate presented by the server
			if (chain.ChainElements.Count != privateChain.ChainElements.Count) return false;

			//lets validate the our chain status
			foreach (var chainStatus in privateChain.ChainStatus)
			{
				//custom CA's that are not in the machine trusted store will always have this status
				//by setting trustRoot = true (default) we skip this error
				if (chainStatus.Status == X509ChainStatusFlags.UntrustedRoot && trustRoot) continue;
				//trustRoot is false so we expected our CA to be in the machines trusted store
				if (chainStatus.Status == X509ChainStatusFlags.UntrustedRoot) return false;
				//otherwise if the chain has any error of any sort return false
				if (chainStatus.Status != X509ChainStatusFlags.NoError) return false;
			}

			var i = 0;
			var found = false;
			//We are going to walk both chains and make sure the thumbprints align
			//while making sure one of the chains certificates presented by the server has our expected CA thumbprint
			foreach (var element in chain.ChainElements)
			{
				var c = element.Certificate.Thumbprint;
				if (c == caCertificate.Thumbprint)
					found = true;

				var cPrivate = privateChain.ChainElements[i].Certificate.Thumbprint;
				//mis aligned certificate chain, return false so we do not accept this certificate
				if (c != cPrivate) return false;
				i++;
			}
			return found;
		}

	}
}
