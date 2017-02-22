using System;
using System.IO;
using Tests.Framework.Configuration;
using Tests.Framework.Integration;
using Tests.Framework.Versions;

namespace Tests.Framework.ManagedElasticsearch.Nodes
{
	/// <summary> Strongly types file system paths for a node </summary>
	public class NodeFileSystem
	{
		private readonly ElasticsearchVersion _version;
		private readonly string _clusterName;

		public string ElasticsearchHome { get; }
		public string Binary => Path.Combine(this.ElasticsearchHome, "bin", "elasticsearch") + ".bat";
		public string PluginBinary =>
			Path.Combine(this.ElasticsearchHome, "bin", (this._version.Major >= 5 ? "elasticsearch-" : "" ) +"plugin") + ".bat";
		public string ConfigPath => Path.Combine(ElasticsearchHome, "config");
		public string DataPath => Path.Combine(ElasticsearchHome, "data", this._clusterName);
		public string LogsPath => Path.Combine(ElasticsearchHome, "logs");
		public string RepositoryPath => Path.Combine(RoamingFolder, "repositories");

		public string RoamingFolder { get; }
		public string AnalysisFolder => Path.Combine(this.ConfigPath, "analysis");
		public string DownloadZipLocation => Path.Combine(this.RoamingFolder, this._version.Zip);
		public string TaskRunnerFile => Path.Combine(this.RoamingFolder, "taskrunner.log");


		//certificates
		public string CertGenBinary => Path.Combine(this.ElasticsearchHome, "bin", "x-pack", "certgen") + ".bat";

		public string CertificateFolderName => "node-certificates";
		public string CertificateNodeName => "node01";
		public string CertificatesPath => Path.Combine(this.ConfigPath, this.CertificateFolderName);
		public string CaCertificate => Path.Combine(this.CertificatesPath, "ca", "ca") + ".crt";
		public string NodePrivateKey => Path.Combine(this.CertificatesPath, this.CertificateNodeName, this.CertificateNodeName) + ".key";
		public string NodeCertificate => Path.Combine(this.CertificatesPath, this.CertificateNodeName, this.CertificateNodeName) + ".crt";

		public NodeFileSystem(ElasticsearchVersion version, string clusterName, string nodeName)
		{
			this._version = version;
			this._clusterName = clusterName;

			var appData = GetApplicationDataDirectory() ?? "/tmp/NEST";
			this.RoamingFolder = Path.Combine(appData, "NEST", this._version.FullyQualifiedVersion);
			this.ElasticsearchHome = Path.Combine(this.RoamingFolder, this._version.FolderInZip);
		}

		private static string GetApplicationDataDirectory()
		{
#if DOTNETCORE
			return Environment.GetEnvironmentVariable("APPDATA");
#else
			return Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
#endif
		}
	}
}
