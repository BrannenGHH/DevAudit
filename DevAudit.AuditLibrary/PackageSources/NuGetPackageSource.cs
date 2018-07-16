using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Xml;
using System.Xml.Linq;

using Versatile;

namespace DevAudit.AuditLibrary
{
    public class NuGetPackageSource : PackageSource
    {
        public override string PackageManagerId => "nuget";

        public override string PackageManagerLabel => "NuGet";

        public override string DefaultPackageManagerConfigurationFile => "packages.config";

        public NuGetPackageSource(Dictionary<string, object> packageSourceOptions, 
                                  EventHandler<EnvironmentEventArgs> messageHandler = null) 
            : base(packageSourceOptions, messageHandler)
        {
              
        }

        /// <summary>
        /// Reads the packages.config file and returns 
        /// </summary>
        /// <param name="o"></param>
        /// <returns></returns>
        public override IEnumerable<Package> GetPackages(params string[] o) ////Get NuGet packages from reading packages.config
        {
            try
            {
                // Load config file
                AuditFileInfo configFile = this.AuditEnvironment.ConstructFile(this.PackageManagerConfigurationFile);
                string byteOrderMarkUtf8 = Encoding.UTF8.GetString(Encoding.UTF8.GetPreamble());
                string xml = configFile.ReadAsText();

                // Remove BOM from beginning of string if it exsists exsists
                if (xml.StartsWith(byteOrderMarkUtf8, StringComparison.Ordinal))
                {
                    int lastIndexOfUtf8 = byteOrderMarkUtf8.Length;
                    xml = xml.Remove(0, lastIndexOfUtf8);
                }

                // Parse XML file
                XElement root = XElement.Parse(xml);
                IEnumerable<Package> packages =
                    from package in root.Elements("package")
                    select new Package("nuget", package.Attribute("id").Value, package.Attribute("version").Value);
                return packages;
            }
            catch (XmlException e)
            {
                throw new Exception("XML exception thrown parsing file: " + this.PackageManagerConfigurationFile, e);
            }
            catch (Exception e)
            {
                throw new Exception("Unknown exception thrown attempting to get packages from file: "
                    + this.PackageManagerConfigurationFile, e);
            }

        }

        public override bool IsVulnerabilityVersionInPackageVersionRange(string vulnerabilityVersion, string packageVersion)
        {
            string message;
            bool r = NuGetv2.RangeIntersect(vulnerabilityVersion, packageVersion, out message);
            if (!r && !string.IsNullOrEmpty(message))
            {
                throw new Exception(message);
            }
            return r;           
        }
    }
}
