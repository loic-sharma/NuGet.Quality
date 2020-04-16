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

            await resource.CopyNupkgToStreamAsync(
                packageId,
                version,
                packageStream,
                cache,
                logger,
                cancellationToken);

            Console.WriteLine($"Downloaded package {packageId} {packageVersion}");

            using PackageArchiveReader packageReader = new PackageArchiveReader(packageStream);
            NuspecReader nuspecReader = await packageReader.GetNuspecReaderAsync(cancellationToken);

            var ctx = new ValidationContext
            {
                PackageStream = packageStream,
                PackageReader = packageReader,
                NuspecReader = nuspecReader,
                Messages = new List<string>(),
            };

            await ValidateAsync(ctx, CancellationToken.None);

            foreach (var message in ctx.Messages) Console.WriteLine(message);

            if (!ctx.Messages.Any()) Console.WriteLine("No messages!");
        }

        public static async Task ValidateAsync(ValidationContext ctx, CancellationToken cancellationToken)
        {
            // TODO: NuGet client validations
            // TODO: Sourcelink?
            // TODO: Check nupkg is well formed?
            // TODO: Check license? Penalize license URL
            await new HasXmlDocs().ValidateAsync(ctx, cancellationToken);
            await new HasSymbols().ValidateAsync(ctx, cancellationToken);
            await new StablePackageHasStableDependencies().ValidateAsync(ctx, cancellationToken);
        }
    }

    public class HasXmlDocs : AbstractValidation
    {
        public override void Validate(ValidationContext ctx)
        {
            var items = new HashSet<string>(
                ctx.PackageReader.GetLibItems().SelectMany(g => g.Items),
                StringComparer.OrdinalIgnoreCase);

            foreach (var item in items)
            {
                if (!Path.GetExtension(item).Equals(".dll", StringComparison.OrdinalIgnoreCase)) continue;

                // The current file is an assembly. It should have a corresponding XML documentation file.
                if (!items.Contains(Path.ChangeExtension(item, "xml")))
                {
                    ctx.Messages.Add("The package is missing XML documentation!");
                    return;
                }
            }
        }
    }

    public class HasSymbols : IValidation
    {
        // https://github.com/dotnet/runtime/blob/4f9ae42d861fcb4be2fcd5d3d55d5f227d30e723/src/libraries/System.Reflection.Metadata/src/System/Reflection/Metadata/PortablePdb/PortablePdbVersions.cs#L41
        private const ushort PortableCodeViewVersionMagic = 0x504d;

        // https://github.com/dotnet/roslyn/blob/b3cbe7abce7633e45d7dd468bde96bfe24ccde47/src/Dependencies/CodeAnalysis.Debugging/PortableCustomDebugInfoKinds.cs#L18
        private static readonly Guid SourceLinkMagic = new Guid("CC110556-A091-4D38-9FEC-25AB9A351A6A");

        private readonly HttpClient _httpClient = new HttpClient();

        public async Task ValidateAsync(ValidationContext ctx, CancellationToken cancellationToken)
        {
            var items = new HashSet<string>(ctx.PackageReader.GetLibItems().SelectMany(g => g.Items));

            foreach (var item in items)
            {
                if (Path.GetExtension(item).ToLowerInvariant() != ".dll") continue;

                await ValidatePackageAssembly(ctx, item, cancellationToken);
            }
        }

        private async Task ValidatePackageAssembly(ValidationContext ctx, string item, CancellationToken cancellationToken)
        {
            Console.WriteLine(item);

            using var fileStream = new MemoryStream();
            using (var rawStream = ctx.PackageReader.GetStream(item))
            {
                await rawStream.CopyToAsync(fileStream, cancellationToken);
                fileStream.Position = 0;
            }

            using var peReader = new PEReader(fileStream);

            // Check if the package has a corresponding symbol file for the assembly.
            var symbolPath = Path.GetDirectoryName(item) + "/" + Path.GetFileNameWithoutExtension(item) + ".pdb";
            if (ctx.PackageReader.GetFiles().Any(path => path == symbolPath))
            {
                // TODO: Check that the PDB and DLL match.
                // See: https://github.com/NuGet/NuGet.Jobs/blob/master/src/Validation.Symbols/SymbolsValidatorService.cs#L190-L249
                var pdbStream = ctx.PackageReader.GetStream(symbolPath);
                if (!HasSourceLinkDebugInformation(pdbStream))
                {
                    ctx.Messages.Add("The NuGet package does not have SourceLink");
                    return;
                }
            }

            // Check if the assembly has embedded symbols.
            if (peReader.ReadDebugDirectory().Any(e => e.Type == DebugDirectoryEntryType.EmbeddedPortablePdb))
            {
                var embeddedEntry = peReader.ReadDebugDirectory().Single(e => e.Type == DebugDirectoryEntryType.EmbeddedPortablePdb);

                using (var embeddedMetadataProvider = peReader.ReadEmbeddedPortablePdbDebugDirectoryData(embeddedEntry))
                {
                    var pdbReader = embeddedMetadataProvider.GetMetadataReader();

                    if (!HasSourceLinkDebugInformation(pdbReader))
                    {
                        ctx.Messages.Add("The NuGet package does not have SourceLink");
                        return;
                    }
                }
            }

            // The assembly does not have symbols within the package. Try to load the symbols from a symbol server.
            // See: https://github.com/dotnet/symstore/blob/16544a43620dfc9d06a907fc1c8970b7f3b671cb/src/Microsoft.FileFormats/PE/PEFile.cs#L172-L184
            var symbolKeys = GetSymbolKeys(peReader);
            var portableSymbolKeys = symbolKeys.Where(k => k.IsPortablePdb).ToList();
            var windowsSymbolKeys = symbolKeys.Where(k => !k.IsPortablePdb).ToList();

            if (portableSymbolKeys.Any())
            {
                using var pdbStream = await GetSymbolsAsync(portableSymbolKeys, cancellationToken);
                if (pdbStream != null)
                {
                    if (!HasSourceLinkDebugInformation(pdbStream))
                    {
                        ctx.Messages.Add("The NuGet package does not have SourceLink");
                    }

                    return;
                }
            }

            if (windowsSymbolKeys.Any())
            {
                using var pdbStream = await GetSymbolsAsync(windowsSymbolKeys, cancellationToken);
                if (pdbStream != null)
                {
                    ctx.Messages.Add("The NuGet package does not have SourceLink");
                    return;
                }
            }

            ctx.Messages.Add("NuGet package does not have symbols");
        }

        private IReadOnlyList<SymbolKey> GetSymbolKeys(PEReader peReader)
        {
            var result = new List<SymbolKey>();
            var checksums = new List<string>();

            foreach (var entry in peReader.ReadDebugDirectory())
            {
                if (entry.Type != DebugDirectoryEntryType.PdbChecksum) continue;

                var data = peReader.ReadPdbChecksumDebugDirectoryData(entry);
                var algorithm = data.AlgorithmName;
                var checksum = data.Checksum.Select(b => b.ToString("x2"));

                checksums.Add($"{algorithm}:{checksum}");
            }

            foreach (var entry in  peReader.ReadDebugDirectory())
            {
                if (entry.Type != DebugDirectoryEntryType.CodeView) continue;

                var data = peReader.ReadCodeViewDebugDirectoryData(entry);
                var isPortable = entry.MinorVersion == PortableCodeViewVersionMagic;

                var signature = data.Guid;
                var age = data.Age;
                var file = Uri.EscapeDataString(Path.GetFileName(data.Path.Replace('\\', '/')).ToLowerInvariant());

                // Portable PDBs, see: https://github.com/dotnet/symstore/blob/83032682c049a2b879790c615c27fbc785b254eb/src/Microsoft.SymbolStore/KeyGenerators/PortablePDBFileKeyGenerator.cs#L84
                // Windows PDBs, see: https://github.com/dotnet/symstore/blob/83032682c049a2b879790c615c27fbc785b254eb/src/Microsoft.SymbolStore/KeyGenerators/PDBFileKeyGenerator.cs#L52
                var symbolId = isPortable
                    ? signature.ToString("N") + "FFFFFFFF"
                    : string.Format("{0}{1:x}", signature.ToString("N"), age);

                result.Add(new SymbolKey
                {
                    IsPortablePdb = isPortable,
                    Checksums = checksums,
                    Key = $"{file}/{symbolId}/{file}",
                });
            }

            return result;
        }

        private async Task<Stream> GetSymbolsAsync(
            IReadOnlyList<SymbolKey> symbolKeys,
            CancellationToken cancellationToken)
        {
            foreach (var symbolKey in symbolKeys)
            {
                var uri = new Uri(new Uri("https://symbols.nuget.org/download/symbols/"), symbolKey.Key);

                using var request = new HttpRequestMessage();
                request.Method = HttpMethod.Get;
                request.RequestUri = uri;

                if (symbolKey.Checksums.Any())
                {
                    request.Headers.Add("SymbolChecksum", string.Join(";", symbolKey.Checksums));
                }

                using (var response = await _httpClient.SendAsync(request, cancellationToken))
                {
                    if (!response.IsSuccessStatusCode)
                    {
                        continue;
                    }

                    var pdbStream = new MemoryStream();
                    await response.Content.CopyToAsync(pdbStream);
                    pdbStream.Position = 0;

                    return pdbStream;
                }
            }

            return null;
        }

        private bool HasSourceLinkDebugInformation(Stream pdbStream)
        {
            using var pdbReaderProvider = MetadataReaderProvider.FromPortablePdbStream(pdbStream);
            var pdbReader = pdbReaderProvider.GetMetadataReader();

            return HasSourceLinkDebugInformation(pdbReader);
        }

        private bool HasSourceLinkDebugInformation(MetadataReader pdbReader)
        {
            foreach (var customDebugInfoHandle in pdbReader.CustomDebugInformation)
            {
                var customDebugInfo = pdbReader.GetCustomDebugInformation(customDebugInfoHandle);
                if (pdbReader.GetGuid(customDebugInfo.Kind) != SourceLinkMagic)
                {
                    continue;
                }

                var sourceLinkContent = pdbReader.GetBlobBytes(customDebugInfo.Value);
                var sourceLinkText = System.Text.Encoding.UTF8.GetString(sourceLinkContent);

                Console.WriteLine("Sourcelink: " + sourceLinkText);
                return true;
            }

            return false;
        }

        private class SymbolKey
        {
            public bool IsPortablePdb { get; set; }
            public IReadOnlyList<string> Checksums { get; set; }
            public string Key { get; set; }
        }
    }

    public class StablePackageHasStableDependencies : AbstractValidation
    {
        public override void Validate(ValidationContext ctx)
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

    public abstract class AbstractValidation : IValidation
    {
        public abstract void Validate(ValidationContext ctx);
        
        public Task ValidateAsync(ValidationContext ctx, CancellationToken cancellationToken)
        {
            Validate(ctx);
            return Task.CompletedTask;
        }

    }

    public interface IValidation
    {
        Task ValidateAsync(ValidationContext ctx, CancellationToken cancellationToken);
    }

    public class ValidationContext
    {
        public Stream PackageStream { get; set; }

        public PackageArchiveReader PackageReader { get; set; }

        public NuspecReader NuspecReader { get; set; }

        public List<string> Messages { get; set; }
    }
}
