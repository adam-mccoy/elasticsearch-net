using System.IO;
using System.IO.Compression;
using Nest;
using Tests.Framework;
using Tests.Framework.ManagedElasticsearch.Clusters;
using Tests.Framework.ManagedElasticsearch.Nodes;
using Tests.Framework.ManagedElasticsearch.Plugins;
using Tests.Framework.ManagedElasticsearch.Tasks.InstallationTasks;

namespace Tests.XPack.Security.Certificates
{
	[RequiresPlugin(ElasticsearchPlugin.XPack)]
	public abstract class SslAndKpiXPackCluster : XPackCluster
	{
		public override bool EnableSsl { get; } = true;
		/// <summary>
		/// Skipping bootstrap validation because they call out to elasticsearch and would force
		/// The ServerCertificateValidationCallback to return true. Since i
		/// </summary>
		public override bool SkipValidation { get; } = true;

		protected override InstallationTaskBase[] AdditionalInstallationTasks => new [] { new EnableSslAndKpiOnCluster() };

		protected override string[] AdditionalServerSettings => new []
		{
			$"xpack.ssl.key={this.Node.FileSystem.NodePrivateKey}",
			$"xpack.ssl.certificate={this.Node.FileSystem.NodeCertificate}",
			$"xpack.ssl.certificate_authorities={this.Node.FileSystem.CaCertificate}",
			"xpack.security.transport.ssl.enabled=true",
			"xpack.security.http.ssl.enabled=true",
		};

		public override ConnectionSettings ClusterConnectionSettings(ConnectionSettings s) =>
			this.ConnectionSettings(s.BasicAuthentication("es_admin", "es_admin"));

		protected abstract ConnectionSettings ConnectionSettings(ConnectionSettings s);


	}

	public class EnableSslAndKpiOnCluster : InstallationTaskBase
	{
		public override void Run(NodeConfiguration config, NodeFileSystem fileSystem)
		{
			//due to a bug in certgen this file needs to live in two places
			var silentModeConfigFile  = Path.Combine(fileSystem.ElasticsearchHome, "certgen") + ".yml";
			var silentModeConfigFileDuplicate  = Path.Combine(fileSystem.ConfigPath, "x-pack", "certgen") + ".yml";
			foreach(var file in new []{silentModeConfigFile, silentModeConfigFileDuplicate})
                if (!File.Exists(file)) File.WriteAllLines(file, new []
                {
                    "instances:",
                    $"    - name : \"{fileSystem.CertificateNodeName}\"",
                });

			var name = fileSystem.CertificateFolderName;
			if (!File.Exists(fileSystem.CaCertificate))
				this.ExecuteBinary(fileSystem.CertGenBinary, "generating ssl certificates for this session",
					"-in", silentModeConfigFile, "-out", $"{name}.zip");

			if (!Directory.Exists(fileSystem.CertificatesPath))
			{
				Directory.CreateDirectory(fileSystem.CertificatesPath);
				var zipLocation  = Path.Combine(fileSystem.ConfigPath, "x-pack", name) + ".zip";
				ZipFile.ExtractToDirectory(zipLocation, fileSystem.CertificatesPath);
			}
		}
	}
}
