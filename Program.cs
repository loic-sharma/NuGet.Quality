using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Threading;
using System.Threading.Tasks;
using NuGet.Common;
using NuGet.Packaging;
using NuGet.Protocol;
using NuGet.Protocol.Core.Types;
using NuGet.Versioning;

namespace NuGet.Quality
{
    public class Program
    {
        public static async Task Main(string packageId, string packageVersion)
        {
            ILogger logger = NullLogger.Instance;
            CancellationToken cancellationToken = CancellationToken.None;

            SourceCacheContext cache = new SourceCacheContext();
            SourceRepository repository = Repository.Factory.GetCoreV3("https://api.nuget.org/v3/index.json");
            FindPackageByIdResource resource = await repository.GetResourceAsync<FindPackageByIdResource>();

            NuGetVersion version = new NuGetVersion(packageVersion);
            using MemoryStream packageStream = new MemoryStream();

            var copied = await resource.CopyNupkgToStreamAsync(
                packageId,
                version,
                packageStream,
                cache,
                logger,
                cancellationToken);
            if (!copied)
            {
                Console.WriteLine("Could not find package");
                return;
            }

            Console.WriteLine($"Downloaded package {packageId} {packageVersion}");

            using PackageArchiveReader packageReader = new PackageArchiveReader(packageStream);
            NuspecReader nuspecReader = await packageReader.GetNuspecReaderAsync(cancellationToken);

            var ctx = new AnalysisContext
            {
                PackageStream = packageStream,
                PackageReader = packageReader,
                PackageFiles = new HashSet<string>(
                    packageReader.GetFiles(),
                    StringComparer.OrdinalIgnoreCase),
                NuspecReader = nuspecReader,
                Messages = new List<string>(),
            };

            // TODO: NuGet client validations
            // TODO: Check nupkg is well formed?
            new HasXmlDocs().Run(ctx);
            new StablePackageHasStableDependencies().Run(ctx);
            new HasValidLicense().Run(ctx);

            await new HasSymbols().RunAsync(ctx, cancellationToken);

            foreach (var message in ctx.Messages) Console.WriteLine(message);

            if (!ctx.Messages.Any()) Console.WriteLine("No messages!");
        }
    }

    public class HasXmlDocs
    {
        public void Run(AnalysisContext ctx)
        {
            foreach (var item in ctx.PackageFiles)
            {
                if (!Path.GetExtension(item).Equals(".dll", StringComparison.OrdinalIgnoreCase)) continue;

                // The current file is an assembly. It should have a corresponding XML documentation file.
                if (!ctx.PackageFiles.Contains(Path.ChangeExtension(item, "xml")))
                {
                    ctx.Messages.Add("The package is missing XML documentation!");
                    return;
                }
            }
        }
    }

    public class StablePackageHasStableDependencies
    {
        public void Run(AnalysisContext ctx)
        {
            if (ctx.NuspecReader.GetVersion().IsPrerelease)
            {
                return;
            }

            // This is a stable package. All its dependencies should be stable as well.
            foreach (var dependencyGroup in ctx.NuspecReader.GetDependencyGroups())
            {
                foreach (var dependency in dependencyGroup.Packages)
                {
                    var versionRange = dependency.VersionRange;
                    if (versionRange.HasLowerBound && versionRange.MinVersion.IsPrerelease)
                    {
                        ctx.Messages.Add("Stable packages should not depend on unstable dependencies");
                        return;
                    }

                    if (versionRange.HasUpperBound && versionRange.MaxVersion.IsPrerelease)
                    {
                        ctx.Messages.Add("Stable packages should not depend on unstable dependencies");
                        return;
                    }
                }
            }
        }
    }

    public class HasValidLicense
    {
        public void Run(AnalysisContext ctx)
        {
            var licenseMetadata = ctx.PackageReader.NuspecReader.GetLicenseMetadata();
            var licenseUrl = ctx.PackageReader.NuspecReader.GetLicenseUrl();

            if (licenseMetadata == null && licenseUrl == null)
            {
                ctx.Messages.Add("Package does not have a license");
                return;
            }

            if (licenseMetadata == null)
            {
                ctx.Messages.Add("Package uses legacy license URL");
                return;
            }
        }
    }

    public class HasSymbols
    {
        private readonly SymbolsClient _symbols = new SymbolsClient(
            new HttpClient(),
            new Uri("https://symbols.nuget.org/download/symbols/"));

        public async Task RunAsync(AnalysisContext ctx, CancellationToken cancellationToken)
        {
            foreach (var item in ctx.PackageFiles)
            {
                if (!Path.GetExtension(item).Equals(".dll", StringComparison.OrdinalIgnoreCase)) continue;

                if (!await AssemblyIsDebuggable(ctx, item, cancellationToken))
                {

                }
            }
        }

        private async Task<bool> AssemblyIsDebuggable(AnalysisContext ctx, string item, CancellationToken cancellationToken)
        {
            using var fileStream = new MemoryStream();
            using (var rawStream = ctx.PackageReader.GetStream(item))
            {
                await rawStream.CopyToAsync(fileStream, cancellationToken);
                fileStream.Position = 0;
            }

            // Check if the package has a corresponding symbol file for the assembly.
            var symbolPath = Path.ChangeExtension(item, "pdb");
            if (ctx.PackageFiles.Contains(symbolPath))
            {
                // TODO: Check that the PDB and DLL match.
                // See: https://github.com/NuGet/NuGet.Jobs/blob/master/src/Validation.Symbols/SymbolsValidatorService.cs#L190-L249
                var pdbStream = ctx.PackageReader.GetStream(symbolPath);
                if (HasSourceLink(pdbStream))
                {
                    ctx.Messages.Add("The NuGet package does not have SourceLink");
                    return false;
                }
            }

            // Check if the assembly has embedded symbols.
            using var peReader = new PEReader(fileStream);
            
            using (var embeddedSymbolsProvider = peReader.GetEmbeddedSymbolsProviderOrNull())
            {
                if (embeddedSymbolsProvider != null)
                {
                    var pdbReader = embeddedSymbolsProvider.GetMetadataReader();

                    if (!pdbReader.HasSourceLink())
                    {
                        ctx.Messages.Add("The NuGet package does not have SourceLink");
                        return false;
                    }
                }
            }

            // The assembly does not have symbols within the package. Try to load the symbols from a symbol server.
            foreach (var symbolKey in peReader.GetSymbolKeys())
            {
                using var pdbStream = await _symbols.GetSymbolsAsync(symbolKey.Key, symbolKey.Checksums, cancellationToken);
                if (pdbStream != null)
                {
                    using var seekablePdbStream = new MemoryStream();
                    await pdbStream.CopyToAsync(seekablePdbStream, cancellationToken);
                    seekablePdbStream.Position = 0;

                    if (!HasSourceLink(seekablePdbStream))
                    {
                        ctx.Messages.Add("The NuGet package does not have SourceLink");
                        return false;
                    }

                    return true;
                }
            }

            ctx.Messages.Add("NuGet package does not have symbols");
            return false;
        }

        private bool HasSourceLink(Stream pdbStream)
        {
            using var pdbReaderProvider = MetadataReaderProvider.FromPortablePdbStream(pdbStream);
            var pdbReader = pdbReaderProvider.GetMetadataReader();

            return pdbReader.HasSourceLink();
        }
    }

    public class AnalysisContext
    {
        public Stream PackageStream { get; set; }

        public PackageArchiveReader PackageReader { get; set; }

        public ISet<string> PackageFiles { get; set; }

        public NuspecReader NuspecReader { get; set; }


        public List<string> Messages { get; set; }
    }
}
