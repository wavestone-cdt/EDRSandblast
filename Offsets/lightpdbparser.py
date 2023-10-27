#!/usr/bin/python3
"""
A python native parser with (many) missing features.
Only support the bare minimum to extract symbols addresses and field offsets in structures
Written from info found here: https://llvm.org/docs/PDB/index.html
"""
from math import ceil
from struct import unpack
from functools import cache, cached_property
from uuid import UUID

try:
    from line_profiler_pycharm import profile
except ImportError:
    profile = lambda x: x


def u32f(f, addr=None):
    if addr is not None:
        f.seek(addr)
    return unpack("<I", f.read(4))[0]


def readat(f, addr, size):
    f.seek(addr)
    return f.read(size)


class MsfStream(object):
    def __init__(self, msf, size, blocks):
        self.msf = msf
        self.size = size
        self.blocks = blocks
        self.cursor = 0

    @profile
    def read(self, size=None):
        if size is not None:
            size = min(self.size - self.cursor, size)
        else:
            size = self.size - self.cursor
        content = b""
        block_size = self.msf.BlockSize
        current_block_index = self.cursor // block_size
        while size:
            current_block = self.blocks[current_block_index]
            current_block_index += 1
            block_offset = self.cursor % block_size
            to_read = min(block_size - block_offset, size)
            self.msf.f.seek(block_size * current_block + block_offset)
            content += self.msf.f.read(to_read)
            self.cursor += to_read
            size -= to_read
        return content

    def seek(self, pos):
        self.cursor = pos

    def peek_u8(self, at=None):
        pos = self.cursor
        u = self.u8(at)
        self.cursor = pos
        return u

    def peek_u16(self, at=None):
        pos = self.cursor
        u = self.u16(at)
        self.cursor = pos
        return u

    def peek_u32(self, at=None):
        pos = self.cursor
        u = self.u32(at)
        self.cursor = pos
        return u

    def u8(self, addr=None):
        if addr is not None:
            self.seek(addr)
        return self.read(1)[0]

    def u16(self, addr=None):
        if addr is not None:
            self.seek(addr)
        return unpack("<H", self.read(2))[0]

    def u32(self, addr=None):
        if addr is not None:
            self.seek(addr)
        return unpack("<I", self.read(4))[0]

    def u64(self, addr=None):
        if addr is not None:
            self.seek(addr)
        return unpack("<Q", self.read(8))[0]

    def cstring(self):
        s = b""
        start = self.cursor
        while b"\x00" not in s:
            s += self.read(32)
        s = s.split(b"\x00", maxsplit=1)[0]
        self.cursor = start + len(s) + 1
        return s


class MsfStreamDirectory(object):
    def __init__(self, msf):
        self.msf = msf

    # @cache
    def __getitem__(self, num_dword):
        StreamDirectoryBlockMapAddr = self.msf.BlockMapAddr * self.msf.BlockSize
        block_number = num_dword * 4 // self.msf.BlockSize
        block_addr = self.msf.BlockSize * u32f(self.msf.f, StreamDirectoryBlockMapAddr + 4 * block_number)
        dword_addr = block_addr + (num_dword * 4) % self.msf.BlockSize
        return u32f(self.msf.f, dword_addr)

    @cached_property
    def NumStreams(self):
        return self[0]

    def StreamSize(self, stream_number):
        return self[1 + stream_number]

    def StreamBlocks(self, stream_number):
        index_streamblocks = 1 + self.NumStreams
        for i in range(stream_number):
            index_streamblocks += ceil(self.StreamSize(i) / self.msf.BlockSize)
        blocks = [
            self[index_streamblocks + b] for b in range(ceil(self.StreamSize(stream_number) / self.msf.BlockSize))
        ]
        return blocks


class PdbInfoStream(MsfStream):
    """
    struct PdbStreamHeader {
      ulittle32_t Version;
      ulittle32_t Signature;
      ulittle32_t Age;
      Guid UniqueId;
    };

    //Named stream hashmap
    // "The on-disk layout of the Named Stream Map consists of 2 components. The first is a buffer of string data prefixed
    // by a 32-bit length. The second is a serialized hash table whose key and value types are both uint32_t. The key is
    // the offset of a null-terminated string in the string data buffer specifying the name of the stream, and the value
    // is the MSF stream index of the stream with said name. Note that although the key is an integer, the hash function
    // used to find the right bucket hashes the string at the corresponding offset in the string data buffer."
    .--------------------.-- +0
    |        Size        |
    .--------------------.-- +4
    |      Capacity      |
    .--------------------.-- +8
    | Present Bit Vector |
    .--------------------.-- +N
    | Deleted Bit Vector |
    .--------------------.-- +M                  ─╮
    |        Key         |                        │
    .--------------------.-- +M+4                 │
    |       Value        |                        │
    .--------------------.-- +M+4+sizeof(Value)   │
             ...                                  ├─ |Capacity| Bucket entries
    .--------------------.                        │
    |        Key         |                        │
    .--------------------.                        │
    |       Value        |                        │
    .--------------------.                       ─╯

    //+ a sequence of
    enum class PdbRaw_FeatureSig : uint32_t {
      VC110 = 20091201,
      VC140 = 20140508,
      NoTypeMerge = 0x4D544F4E,
      MinimalDebugInfo = 0x494E494D,
    };
    """

    @cached_property
    def Version(self):
        return self.u32(0)

    @cached_property
    def Signature(self):
        return self.u32(4)

    @cached_property
    def Age(self):
        return self.u32(8)

    @cached_property
    def Guid(self):
        return UUID(bytes_le=readat(self, 12, 16))

    """
    Format explained here: https://github.com/willglynn/pdb/blob/b052964e09d03eb190c8a60dc76344150ff8a9df/src/pdbi.rs#L99
    """

    @cached_property
    def NamedStreamMap(self):
        string_buffer_size = self.u32(3 * 4 + 16)
        strings_buffer = self.read(string_buffer_size)
        size_hashmap = self.u32()
        capacity_hashmap = self.u32()  # unused
        present_bit_vector_word_count = self.u32()
        present_bit_vector = 0
        for i in range(present_bit_vector_word_count):
            present_bit_vector |= self.u32() << (32 * i)
        deleted_bit_vector_word_count = self.u32()
        deleted_bit_vector = 0
        for i in range(deleted_bit_vector_word_count):
            deleted_bit_vector |= self.u32() << (32 * i)
        named_streams_ids = dict()
        count_present = 0
        for i in range(capacity_hashmap):
            if present_bit_vector & (1 << i):
                key = self.u32()
                value = self.u32()
                count_present += 1
                if not (deleted_bit_vector & (1 << i)):
                    assert key == 0 or strings_buffer[key - 1 : key] == b"\x00"
                    stream_name = strings_buffer[key:].split(b"\x00")[0]
                    stream_id = value
                    named_streams_ids[stream_name.decode()] = self.msf.Stream(stream_id)
        assert count_present == size_hashmap
        return named_streams_ids


class SymRecordStream(MsfStream):
    # complete with https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h#L2900
    # if a value is missing
    REC_TYPES = {
        0x110E: "S_PUB32",  # a public symbol (CV internal reserved)
        0x1125: "S_PROCREF",  # Reference to a procedure
        0x1127: "S_LPROCREF",  # Local Reference to a procedure
        0x1128: "S_ANNOTATIONREF",  # Reference to an S_ANNOTATION symbol
    }

    def __init__(self, msf, size, blocks):
        MsfStream.__init__(self, msf, size, blocks)
        self.symbols = dict()
        self.next_to_parse_offset = 0

    def __iter__(self):
        self.cursor = 0
        return self

    def __next__(self):
        offset = None
        while offset is None:
            if self.cursor == self.size:
                raise StopIteration
            if self.size - self.cursor < 4:
                raise ValueError

            record_length = self.u16()
            record_end = self.cursor + record_length
            record_type = self.u16()

            if self.size - self.cursor < record_length - 2:
                raise ValueError

            match self.REC_TYPES[record_type]:
                case "S_PUB32":
                    flags, offset, segment = unpack("<IIH", self.read(10))
                    name = self.cstring()
                    self.cursor = record_end
                    return "S_PUB32", offset, name, segment
                case "S_LPROCREF" | "S_PROCREF":
                    """
                    sumName = self.u32()  # SUC of the name
                    ibSym = offset = self.u32()  # Offset of actual symbol in $$Symbols
                    imod = self.u16()  # Module containing the actual symbol
                    name = self.read(record_length - 12)

                    # ignore for the moment
                    """
                    offset = name = None
                case "S_ANNOTATIONREF":
                    offset = name = None
                case _:
                    offset = name = None
                    raise ValueError(f"{self.REC_TYPES[record_type]} : not implemented")
            self.seek(record_end)

    def search_and_cache_symbols(self, symbolname: str):
        symbolname_raw = symbolname.encode()
        if symbolname_raw not in self.symbols:
            saved_cursor = self.cursor
            self.cursor = self.next_to_parse_offset
            while self.cursor != self.size:
                try:
                    _, offset, name, segment = self.__next__()
                except StopIteration:
                    continue
                self.symbols[name] = (offset, segment)
                if name == symbolname_raw:
                    break
            else:
                return (None, None)
            self.next_to_parse_offset = self.cursor
            self.cursor = saved_cursor
        return self.symbols[symbolname_raw]


class DBIStream(MsfStream):
    """
    struct DbiStreamHeader {
      int32_t VersionSignature;             // 0
      uint32_t VersionHeader;               // 4
      uint32_t Age;                         // 8
      uint16_t GlobalStreamIndex;           // 12
      uint16_t BuildNumber;                 // 14
      uint16_t PublicStreamIndex;           // 16
      uint16_t PdbDllVersion;               // 18
      uint16_t SymRecordStream;             // 20
      uint16_t PdbDllRbld;                  // 22
      int32_t ModInfoSize;                  // 24
      int32_t SectionContributionSize;      // 28
      int32_t SectionMapSize;               // 32
      int32_t SourceInfoSize;               // 36
      int32_t TypeServerMapSize;            // 40
      uint32_t MFCTypeServerIndex;          // 44
      int32_t OptionalDbgHeaderSize;        // 48
      int32_t ECSubstreamSize;              // 52
      uint16_t Flags;                       // 56
      uint16_t Machine;                     // 58
      uint32_t Padding;                     // 60
    };
    """

    @cached_property
    def SymRecordStream(self):
        stream_id = self.peek_u16(20)
        return SymRecordStream(
            self.msf,
            self.msf.StreamDirectory.StreamSize(stream_id),
            self.msf.StreamDirectory.StreamBlocks(stream_id),
        )

    @cached_property
    def ModInfoSize(self):
        return self.peek_u32(24)

    @cached_property
    def SectionContributionSize(self):
        return self.peek_u32(28)

    @cached_property
    def SectionMapSize(self):
        return self.peek_u32(32)

    @cached_property
    def SourceInfoSize(self):
        return self.peek_u32(36)

    @cached_property
    def TypeServerMapSize(self):
        return self.peek_u32(40)

    @cached_property
    def OptionalDbgHeaderSize(self):
        return self.peek_u32(48)

    @cached_property
    def ECSubstreamSize(self):
        return self.peek_u32(52)

    @cached_property
    def SectionHeadersStream(self):
        """
        See https://llvm.org/docs/PDB/DbiStream.html#optional-debug-header-stream
        """
        if self.OptionalDbgHeaderSize // 2 < 6:
            raise ValueError("OptionalDbgHeader not present or does not contain Section Header Data")
        stream_id = self.peek_u16(
            64  # DBI Header size
            + self.ModInfoSize
            + self.SectionContributionSize
            + self.SectionMapSize
            + self.SourceInfoSize
            + self.TypeServerMapSize
            + self.ECSubstreamSize
            + 0  # Optional Debug Header Stream starts here
            + 2 * 5  # uint16_t DbgStreamArray[5] contains the stream number of the section headers
        )
        return SectionHeaderStream(
            self.msf, self.msf.StreamDirectory.StreamSize(stream_id), self.msf.StreamDirectory.StreamBlocks(stream_id)
        )


class SectionHeaderStream(MsfStream):
    """
    typedef struct _IMAGE_SECTION_HEADER {
      BYTE  Name[8];
      union {
        DWORD PhysicalAddress;
        DWORD VirtualSize;
      } Misc;
      DWORD VirtualAddress;
      DWORD SizeOfRawData;
      DWORD PointerToRawData;
      DWORD PointerToRelocations;
      DWORD PointerToLinenumbers;
      WORD  NumberOfRelocations;
      WORD  NumberOfLinenumbers;
      DWORD Characteristics;
    } IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
    """

    class SectionHeader(object):
        def __init__(self, data):
            (
                self.Name,
                self.VirtualSize,
                self.VirtualAddress,
                self.SizeOfRawData,
                self.PointerToRawData,
                self.PointerToRelocations,
                self.PointerToLinenumbers,
                self.NumberOfRelocations,
                self.NumberOfLinenumbers,
                self.Characteristics,
            ) = unpack("8sIIIIIIHHI", data)

    @cached_property
    def NumberOfSections(self):
        assert self.size % 40 == 0
        return self.size // 40

    def __iter__(self):
        self.cursor = 0
        return self

    def __next__(self):
        if self.cursor >= self.size:
            raise StopIteration
        return SectionHeaderStream.SectionHeader(self.read(40))

    def __getitem__(self, section_index):
        if section_index >= self.NumberOfSections:
            raise ValueError(f"Section number {section_index} does not exist")
        self.cursor = section_index * 40
        return SectionHeaderStream.SectionHeader(self.read(40))


class TPIorIPStream(MsfStream):
    """
    struct TpiStreamHeader {
      uint32_t Version;
      uint32_t HeaderSize;
      uint32_t TypeIndexBegin;
      uint32_t TypeIndexEnd;
      uint32_t TypeRecordBytes;

      uint16_t HashStreamIndex;
      uint16_t HashAuxStreamIndex;
      uint32_t HashKeySize;
      uint32_t NumHashBuckets;

      int32_t HashValueBufferOffset;
      uint32_t HashValueBufferLength;

      int32_t IndexOffsetBufferOffset;
      uint32_t IndexOffsetBufferLength;

      int32_t HashAdjBufferOffset;
      uint32_t HashAdjBufferLength;
    };
    """

    REC_TYPES = {
        0x1001: "LF_MODIFIER",
        0x1002: "LF_POINTER",
        0x1008: "LF_PROCEDURE",
        0x1201: "LF_ARGLIST",
        0x1203: "LF_FIELDLIST",
        0x1205: "LF_BITFIELD",
        0x1404: "LF_INDEX",
        0x1502: "LF_ENUMERATE",
        0x1503: "LF_ARRAY",
        0x1505: "LF_STRUCTURE",
        0x1506: "LF_UNION",
        0x1507: "LF_ENUM",
        0x150D: "LF_MEMBER",
        0x1605: "LF_STRING_ID",
        0x1606: "LF_UDT_SRC_LINE",
    }

    def __init__(self, msf, size, blocks):
        MsfStream.__init__(self, msf, size, blocks)
        self.filter = None
        self.type_index = self.TypeIndexBegin
        self.types = dict()
        self.REC_TYPES_ids = {self.REC_TYPES[k]: k for k in self.REC_TYPES}
        self.types_parsed = False

    @cached_property
    def HeaderSize(self):
        return self.u32(4)

    @cached_property
    def TypeIndexBegin(self):
        return self.u32(8)

    @cached_property
    def TypeRecordBytes(self):
        return self.u32(16)

    def skip_padding(self):
        b = self.u8()
        self.cursor -= 1
        if b in (0xF1, 0xF2, 0xF3):
            padding_size = b & 0xF
            # assert b"\xF3\xF2\xF1".endswith(self.read(padding_size))
            self.cursor += padding_size

    def unsigned(self):
        leaf = self.u16()
        if leaf < 0x8000:
            return leaf
        match leaf:
            case 0x8000:  # LF_CHAR
                return self.u8()
            case 0x8002:  # LF_SHORT
                return self.u16()
            case 0x8003 | 0x8004:  # LF_LONG |LF_ULONG
                return self.u32()
            case 0x800A:  # LF_SHORT
                return self.u64()
            case _:
                raise ValueError

    def __iter__(self):
        self.type_index = self.TypeIndexBegin
        self.cursor = self.HeaderSize
        return self

    def __next__(self):
        leaf_entry = None
        while leaf_entry is None:
            if self.cursor == self.size:
                self.types_parsed = True
                raise StopIteration
            if self.size - self.cursor < 4:
                raise ValueError

            record_length = self.u16()
            record_end = self.cursor + record_length
            if self.size < record_end:
                raise ValueError

            if self.filter is not None and self.peek_u16() not in self.filter:
                self.cursor = record_end
                self.type_index += 1
                continue
            leaf_entry = self.parse_one_leaf_entry(record_end)
            self.types[self.type_index] = leaf_entry
            self.type_index += 1

            if self.cursor > record_end:
                raise ValueError
            if self.cursor < record_end:
                end = self.read(record_end - self.cursor)
                if not b"\xf3\xf2\xf1".endswith(end):
                    raise ValueError(f"Unparsed data: {end} for record {leaf_entry}")

        return leaf_entry

    def parse_one_leaf_entry(self, record_end):
        record_type = self.u16()

        if record_type not in self.REC_TYPES:
            raise ValueError(f"Record {hex(record_type)} not handled")

        match self.REC_TYPES.get(record_type, "???"):
            case "LF_MODIFIER":
                utype = self.u32()
                modifier = self.u16()
                record = (utype, modifier)
            case "LF_POINTER":
                utype = self.u32()
                attr = self.u32()
                if ((attr >> 5) & 7) in (2, 3):  # ptrmode == Member or MemberFunction
                    raise ValueError
                record = (utype, attr)
            case "LF_STRUCTURE":
                count = self.u16()
                properties = self.u16()
                has_unique_name = (properties & 0x200) != 0
                fields = self.u32()
                derived_from = self.u32()
                vtable_shape = self.u32()
                size = self.unsigned()
                name = self.cstring()
                unique_name = self.cstring() if has_unique_name else None
                record = (
                    count,
                    properties,
                    fields,
                    derived_from,
                    vtable_shape,
                    size,
                    name,
                )
            case "LF_FIELDLIST":
                fields = list()
                continuation = None
                while self.cursor < record_end:
                    next_field = self.u16()
                    if self.REC_TYPES[next_field] == "LF_INDEX":
                        continuation = self.u32()
                    else:
                        self.cursor -= 2
                        fields.append(self.parse_one_leaf_entry(record_end))
                    self.skip_padding()
                record = (fields, continuation)
            case "LF_MEMBER":
                attributes = self.u16()
                field_type = self.u32()
                offset = self.unsigned()
                name = self.cstring()
                record = (attributes, field_type, offset, name)
            case "LF_ARGLIST":
                count = self.u32()
                arglist = [self.u32() for _ in range(count)]
                record = arglist
            case "LF_PROCEDURE":
                return_type = self.u32()
                attributes = self.u16()
                parameter_count = self.u16()
                argument_list = self.u32()
                record = (return_type, attributes, parameter_count, argument_list)
            case "LF_ARRAY":
                element_type = self.u32()
                indexing_type = self.u32()
                size = self.unsigned()
                pad = self.cstring()
                assert pad == b""
                record = (element_type, indexing_type, size)
            case "LF_UNION":
                count = self.u16()
                properties = self.u16()
                has_unique_name = (properties & 0x200) != 0
                fields = self.u32()
                size = self.unsigned()
                name = self.cstring()
                unique_name = self.cstring() if has_unique_name else None
                record = (
                    count,
                    properties,
                    fields,
                    size,
                    name,
                )
            case "LF_ENUMERATE":
                attributes = self.u16()
                value = self.unsigned()
                name = self.cstring()
                record = (attributes, value, name)
            case "LF_ENUM":
                count = self.u16()
                properties = self.u16()
                has_unique_name = (properties & 0x200) != 0
                underlying_type = self.u32()
                fields = self.u32()
                name = self.cstring()
                unique_name = self.cstring() if has_unique_name else None
                record = (
                    count,
                    properties,
                    underlying_type,
                    fields,
                    name,
                )
            case "LF_BITFIELD":
                underlying_type = self.u32()
                length = self.u8()
                position = self.u8()
                record = (underlying_type, length, position)
            case _:
                record = ()
                raise ValueError(
                    f"Record {hex(record_type)} / {self.REC_TYPES.get(record_type, '???')}  : not implemented"
                )

        return self.REC_TYPES[record_type], record


import io


class Msf(object):
    def __init__(self, path=None, content=None):
        if content is not None:
            self.f = f = io.BytesIO(content)
        else:
            with open(path, "rb") as f_ondisk:
                self.f = f = io.BytesIO(f_ondisk.read())
        FileMagic = f.read(32)
        assert FileMagic == b"Microsoft C/C++ MSF 7.00\r\n" + bytes.fromhex("1A 44 53 00 00 00")
        self.BlockSize = blockSize = u32f(f)
        self.FreeBlockMapBlock = u32f(f)
        self.NumBlocks = u32f(f)
        self.NumDirectoryBytes = u32f(f)
        self.Unknown = u32f(f)
        self.BlockMapAddr = u32f(f)
        self.StreamDirectory = MsfStreamDirectory(self)

    def __del__(self):
        self.f.close()

    @cache
    def Stream(self, stream_number):
        return MsfStream(
            self,
            self.StreamDirectory.StreamSize(stream_number),
            self.StreamDirectory.StreamBlocks(stream_number),
        )


class Pdb(Msf):
    @cached_property
    def PDBStream(self):
        return PdbInfoStream(
            self,
            self.StreamDirectory.StreamSize(1),
            self.StreamDirectory.StreamBlocks(1),
        )

    @cached_property
    def DBIStream(self):
        return DBIStream(
            self,
            self.StreamDirectory.StreamSize(3),
            self.StreamDirectory.StreamBlocks(3),
        )

    @cached_property
    def TPIStream(self):
        return TPIorIPStream(
            self,
            self.StreamDirectory.StreamSize(2),
            self.StreamDirectory.StreamBlocks(2),
        )

    @cached_property
    def IPIStream(self):
        return TPIorIPStream(
            self,
            self.StreamDirectory.StreamSize(4),
            self.StreamDirectory.StreamBlocks(4),
        )

    def get_field_offset(self, structname, fieldname):
        tpistream = self.TPIStream
        if not tpistream.types_parsed:
            save_filter = tpistream.filter
            tpistream.filter = [
                tpistream.REC_TYPES_ids["LF_FIELDLIST"],
                tpistream.REC_TYPES_ids["LF_STRUCTURE"],
            ]
            for _ in tpistream:
                pass
            tpistream.filter = save_filter

        structname = structname.encode()
        for struct_id, t in tpistream.types.items():
            if t[0] == "LF_STRUCTURE":
                if t[1][2] != 0 and t[1][6] == structname:
                    break
        else:
            raise ValueError(f"Structure {structname} not found in PDB")
        fieldlist_id = t[1][2]
        fieldlist = tpistream.types[fieldlist_id][1][0]
        fieldname = fieldname.encode()
        for field in fieldlist:
            if fieldname == field[1][3]:
                break
        else:
            raise ValueError(f"Field {fieldname} not found in structure {structname}")
        field_offset = field[1][2]
        return field_offset

    def get_symbol_offset(self, symbol: str) -> int:
        offset, segment = self.DBIStream.SymRecordStream.search_and_cache_symbols(symbol)
        if offset == segment == None:
            return None
        section_virtual_address = self.DBIStream.SectionHeadersStream[segment - 1].VirtualAddress
        return section_virtual_address + offset
