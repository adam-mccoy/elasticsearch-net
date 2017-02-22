using System;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Elasticsearch.Net;
using FluentAssertions;
using Nest;
using Tests.Framework;
using Tests.Framework.Integration;
using HttpMethod = Elasticsearch.Net.HttpMethod;

namespace Tests.XPack.Security.Certificates
{
	public class DenyAllCertificatesCluster : SslAndKpiXPackCluster
	{
		protected override ConnectionSettings ConnectionSettings(ConnectionSettings s) => s
			.ServerCertificateValidationCallback((o, certificate, chain, errors) => false)
			.ServerCertificateValidationCallback(CertificateValidations.DenyAll);
	}
	public class DenyAllSslCertificatesApiTests : ConnectionErrorTestBase<DenyAllCertificatesCluster>
	{
		public DenyAllSslCertificatesApiTests(DenyAllCertificatesCluster cluster, EndpointUsage usage) : base(cluster, usage) { }
		[I] public async Task UsedHttps() => await AssertOnAllResponses(r => r.ApiCall.Uri.Scheme.Should().Be("https"));

		protected override void AssertException(WebException e) =>
			e.Message.Should().Contain("Could not establish trust relationship for the SSL/TLS secure channel.");

		protected override void AssertException(HttpRequestException e) { }

	}

	public class AllowAllCertificatesCluster : SslAndKpiXPackCluster
	{
		protected override ConnectionSettings ConnectionSettings(ConnectionSettings s) => s
			.ServerCertificateValidationCallback((o, certificate, chain, errors) => true)
			.ServerCertificateValidationCallback(CertificateValidations.AllowAll);
	}
	public class AllowAllSllCertificatesApiTests : CanConnectTestBase<AllowAllCertificatesCluster>
	{
		public AllowAllSllCertificatesApiTests(AllowAllCertificatesCluster cluster, EndpointUsage usage) : base(cluster, usage) { }
		[I] public async Task UsedHttps() => await AssertOnAllResponses(r => r.ApiCall.Uri.Scheme.Should().Be("https"));
	}

	public class EasyCaValidationCluster : SslAndKpiXPackCluster
	{
		protected override ConnectionSettings ConnectionSettings(ConnectionSettings s) => s
			.ServerCertificateValidationCallback(
				CertificateValidations.Authority(new X509Certificate(this.Node.FileSystem.CaCertificate))
			);
	}
	[SkipVersion("<5.4.0", "certgen does not include CA in chain of certificate yet")]
	public class CustomCertificateAuthorityApiTests : CanConnectTestBase<EasyCaValidationCluster>
	{
		public CustomCertificateAuthorityApiTests(EasyCaValidationCluster cluster, EndpointUsage usage) : base(cluster, usage) { }
		[I] public async Task UsedHttps() => await AssertOnAllResponses(r => r.ApiCall.Uri.Scheme.Should().Be("https"));
	}
}
