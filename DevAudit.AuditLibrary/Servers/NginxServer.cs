﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;
using Alpheus;

namespace DevAudit.AuditLibrary
{
    public class NginxServer : ApplicationServer
    {
        #region Constructors
        public NginxServer(Dictionary<string, object> server_options, EventHandler<EnvironmentEventArgs> message_handler) : base(server_options, 
            new Dictionary<PlatformID, string[]>()
            {
                { PlatformID.Unix, new string[] {"find", "@", "*bin", "nginx"} },
                { PlatformID.Win32NT, new string[] { "@", "nginx.exe" } }
            },
            new Dictionary<PlatformID, string[]>()
            {
                { PlatformID.Unix, new string[] { "@", "etc", "nginx", "nginx.conf" } },
                { PlatformID.Win32NT, new string[] { "@", "conf", "nginx.conf" } }
            }, new Dictionary<string, string[]>(), new Dictionary<string, string[]>(), message_handler)
        {
            if (this.ApplicationBinary != null)
            {
                this.ApplicationFileSystemMap["nginx"] = this.ApplicationBinary;
            }
        }
        #endregion

        #region Overriden properties
        public override string ServerId { get { return "nginx"; } }

        public override string ServerLabel { get { return "Nginx"; } }

        public override PackageSource PackageSource => this as PackageSource;
        #endregion

        #region Overriden methods
        protected override string GetVersion()
        {
            AuditEnvironment.ProcessExecuteStatus process_status;
            string process_output;
            string process_error;
            AuditEnvironment.Execute(ApplicationBinary.FullName, "-v", out process_status, out process_output, out process_error);
            if (process_status == AuditEnvironment.ProcessExecuteStatus.Completed && (process_output.Contains("nginx version: ") || process_error.Contains("nginx version: ")))
            {
                if (!string.IsNullOrEmpty(process_error) && string.IsNullOrEmpty(process_output))
                {
                    process_output = process_error;
                }
                this.Version = process_output.Substring("nginx version: ".Length);
                this.VersionInitialised = true;
                this.AuditEnvironment.Success("Got Nginx version {0}.", this.Version);
                return this.Version;
            }
            else if (process_output.Contains("nginx version: ") || process_error.Contains("nginx version: "))
            {
                if (!string.IsNullOrEmpty(process_error) && string.IsNullOrEmpty(process_output))
                {
                    process_output = process_error;
                }
                this.Version = process_output.Substring("nginx version: ".Length);
                this.VersionInitialised = true;
                this.AuditEnvironment.Success("Got Nginx version {0}.", this.Version);
                return this.Version;
            }
            else
            {
                throw new Exception(string.Format("Did not execute process {0} successfully or could not parse output. Process output: {1}.\nProcess error: {2}.", ApplicationBinary.Name, process_output, process_error));
            }
        }

        protected override Dictionary<string, IEnumerable<Package>> GetModules()
        {
            Dictionary<string, IEnumerable<Package>> m = new Dictionary<string, IEnumerable<Package>>
            {
                {"nginx", new List<Package> {new Package(this.PackageManagerId, "nginx", this.Version) }}
            };
            this.ModulePackages = m;
            this.PackageSourceInitialized = this.ModulesInitialised = true;
            return this.ModulePackages;
        }

        protected override IConfiguration GetConfiguration()
        {
            Nginx nginx = new Nginx(this.ConfigurationFile, this.AlpheusEnvironment);
            if (nginx.ParseSucceded)
            {
                this.Configuration = nginx;
                this.ConfigurationInitialised = true;
            }
            else
            {
                this.AuditEnvironment.Error("Could not parse configuration from {0}.", nginx.FullFilePath);
                if (nginx.LastParseException != null) this.AuditEnvironment.Error(nginx.LastParseException);
                if (nginx.LastIOException != null) this.AuditEnvironment.Error(nginx.LastIOException);
                this.Configuration = null;
                this.ConfigurationInitialised = false;
            }
            return this.Configuration;
        }

        public override bool IsConfigurationRuleVersionInServerVersionRange(string configuration_rule_version, string server_version)
        {
            return (configuration_rule_version == server_version) || configuration_rule_version == ">0";
        }
        
        public override IEnumerable<Package> GetPackages(params string[] o)
        {
            if (!this.ModulesInitialised) throw new InvalidOperationException("Modules must be initialised before GetPackages is called.");
            return this.GetModules()["nginx"];
        }

        public override bool IsVulnerabilityVersionInPackageVersionRange(string vulnerabilityVersion, string packageVersion)
        {
            return vulnerabilityVersion == packageVersion;
        }
        #endregion
    }
}
