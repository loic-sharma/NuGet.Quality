using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;

namespace NuGet.Quality
{
    public static class MetadataExtensions
    {
        // https://github.com/dotnet/runtime/blob/4f9ae42d861fcb4be2fcd5d3d55d5f227d30e723/src/libraries/System.Reflection.Metadata/src/System/Reflection/Metadata/PortablePdb/PortablePdbVersions.cs#L41
        private const ushort PortableCodeViewVersionMagic = 0x504d;

        // https://github.com/dotnet/roslyn/blob/b3cbe7abce7633e45d7dd468bde96bfe24ccde47/src/Dependencies/CodeAnalysis.Debugging/PortableCustomDebugInfoKinds.cs#L18
        private static readonly Guid SourceLinkMagic = new Guid("CC110556-A091-4D38-9FEC-25AB9A351A6A");

        public static MetadataReaderProvider GetEmbeddedSymbolsProviderOrNull(this PEReader peReader)
        {
            foreach (var entry in peReader.ReadDebugDirectory())
            {
                if (entry.Type != DebugDirectoryEntryType.EmbeddedPortablePdb)
                {
                    continue;
                }

                return peReader.ReadEmbeddedPortablePdbDebugDirectoryData(entry);
            }

            return null;
        }

        public static IReadOnlyList<SymbolKey> GetSymbolKeys(this PEReader peReader)
        {
            // See: https://github.com/dotnet/symstore/blob/16544a43620dfc9d06a907fc1c8970b7f3b671cb/src/Microsoft.FileFormats/PE/PEFile.cs#L172-L184
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

            foreach (var entry in peReader.ReadDebugDirectory())
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
                    Key = $"{file}/{symbolId}/{file}",
                    Checksums = checksums,
                });
            }

            return result;
        }

        public static bool HasSourceLink(this MetadataReader reader)
        {
            foreach (var customDebugInfoHandle in reader.CustomDebugInformation)
            {
                var customDebugInfo = reader.GetCustomDebugInformation(customDebugInfoHandle);
                if (reader.GetGuid(customDebugInfo.Kind) == SourceLinkMagic)
                {
                    //var sourceLinkContent = pdbReader.GetBlobBytes(customDebugInfo.Value);
                    //var sourceLinkText = System.Text.Encoding.UTF8.GetString(sourceLinkContent);

                    //Console.WriteLine("Sourcelink: " + sourceLinkText);
                    return true;
                }
            }

            return false;
        }
    }

    public class SymbolKey
    {
        public string Key { get; set; }
        public IReadOnlyList<string> Checksums { get; set; }
    }
}
