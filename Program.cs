using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
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
            var items = new HashSet<string>(ctx.PackageReader.GetLibItems().SelectMany(g => g.Items));

            foreach (var item in items)
            {
                if (Path.GetExtension(item).ToLowerInvariant() != ".dll") continue;

                // The current file is an assembly. It should have a corresponding XML documentation file.
                // TODO: Is the "/" the right thing to use here? Can a NuGet package use "\"?
                if (!items.Contains(Path.GetDirectoryName(item) + "/" + Path.GetFileNameWithoutExtension(item) + ".xml"))
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

        public async Task ValidateAsync(ValidationContext ctx, CancellationToken cancellationToken)
        {
            var httpClient = new HttpClient();
            var items = new HashSet<string>(ctx.PackageReader.GetLibItems().SelectMany(g => g.Items));

            foreach (var item in items)
            {
                if (Path.GetExtension(item).ToLowerInvariant() != ".dll") continue;

                // Check if the package has a corresponding symbol file for the assembly.
                var symbolPath = Path.GetDirectoryName(item) + "/" + Path.GetFileNameWithoutExtension(item) + ".pdb";
                if (items.Contains(symbolPath))
                {
                    // TODO: Check that the PDB and DLL match.
                    // See: https://github.com/NuGet/NuGet.Jobs/blob/master/src/Validation.Symbols/SymbolsValidatorService.cs#L190-L249
                    //continue;
                }

                // TODO: Check if the symbols are embedded in the assembly.
                using var fileStream = new MemoryStream();
                using (var rawStream = ctx.PackageReader.GetStream(item))
                {
                    await rawStream.CopyToAsync(fileStream, cancellationToken);
                    fileStream.Position = 0;
                }

                using var reader = new PEReader(fileStream);

                var debugEntries = reader.ReadDebugDirectory().ToList();

                Console.WriteLine(item);

                // Phase 1 - check if the DLL has embedded symbols.
                // TODO: Is this right??
                if (reader.ReadDebugDirectory().Any(e => e.Type == DebugDirectoryEntryType.EmbeddedPortablePdb))
                {
                    //continue;
                }

                // TODO: Check symbol servers.
                // See: https://github.com/dotnet/symstore/blob/16544a43620dfc9d06a907fc1c8970b7f3b671cb/src/Microsoft.FileFormats/PE/PEFile.cs#L172-L184
                foreach (var entry in reader.ReadDebugDirectory())
                {
                    if (entry.Type != DebugDirectoryEntryType.CodeView) continue;

                    var data = reader.ReadCodeViewDebugDirectoryData(entry);
                    var isPortable = entry.MinorVersion == PortableCodeViewVersionMagic;
                    var signature = data.Guid;
                    var age = data.Age;
                    var file = Uri.EscapeDataString(Path.GetFileName(data.Path.Replace('\\', '/')).ToLowerInvariant());

                    // Portable PDBs, see: https://github.com/dotnet/symstore/blob/83032682c049a2b879790c615c27fbc785b254eb/src/Microsoft.SymbolStore/KeyGenerators/PortablePDBFileKeyGenerator.cs#L84
                    // Windows PDBs, see: https://github.com/dotnet/symstore/blob/83032682c049a2b879790c615c27fbc785b254eb/src/Microsoft.SymbolStore/KeyGenerators/PDBFileKeyGenerator.cs#L52
                    var symbolId = isPortable
                        ? signature.ToString("N") + "FFFFFFFF"
                        : string.Format("{0}{1:x}", signature.ToString("N"), age);

                    Console.WriteLine();
                    Console.WriteLine(file);
                    Console.WriteLine(symbolId);

                    var uri = new Uri(new Uri("https://symbols.nuget.org/download/symbols/"), $"{file}/{symbolId}/{file}");

                    // TODO
                    using var request = new HttpRequestMessage();
                    request.Method = HttpMethod.Get;
                    request.RequestUri = uri;
                    request.Headers.Add("SymbolChecksum", string.Join(";", new[] { "test", "hello" } ));

                    var response = await httpClient.SendAsync(request, cancellationToken);
                    Console.WriteLine(response.StatusCode + " " + uri);
                }
            }
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
