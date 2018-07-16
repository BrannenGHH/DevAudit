﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Newtonsoft.Json;

namespace DevAudit.AuditLibrary
{
    public class Package : IPackage
    {
        [JsonProperty("pm")]
        public string PackageManager { get; set; }

        [JsonProperty("group")]
        public string Group { get; set; }

        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("version")]
        public string Version { get; set; }

        [JsonProperty("vendor")]
        public string Vendor { get; set; }

        [JsonIgnore]
        public string Architecture { get; set; }

        public Package(string packageManager, string applicationName, string version, string vendor = null, string group = null, string architecture = null)
        {
            this.PackageManager = packageManager;
            this.Name = applicationName;
            this.Version = version;
            if (!string.IsNullOrEmpty(vendor)) this.Vendor = vendor;
            if (!string.IsNullOrEmpty(group)) this.Group = group;
            if (!string.IsNullOrEmpty(architecture)) this.Architecture = architecture;
        }
    }
}


