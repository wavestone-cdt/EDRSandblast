#include <Windows.h>

typedef DWORD ulittle32_t;

typedef struct SuperBlock_t {
	char FileMagic[0x20];
	ulittle32_t BlockSize;
	ulittle32_t FreeBlockMapBlock;
	ulittle32_t NumBlocks;
	ulittle32_t NumDirectoryBytes;
	ulittle32_t Unknown;
	ulittle32_t BlockMapAddr;
}SuperBlock;


/*
struct StreamDirectory {
	ulittle32_t NumStreams;
	ulittle32_t StreamSizes[NumStreams];
	ulittle32_t StreamBlocks[NumStreams][];
};
*/

typedef struct PdbInfoStreamHeader_t {
	DWORD Version;
	DWORD Signature;
	DWORD Age;
	GUID UniqueId;
} PdbInfoStreamHeader;

PVOID extractGuidFromPdb(LPWSTR filepath) {
	GUID* guid = NULL;
    HANDLE hFile = CreateFileW(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return NULL;
	}
    HANDLE hMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hMapping == NULL) {
		goto clean_file;
	}
    PBYTE filemap = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
	if (filemap == NULL) {
		goto clean_mapping;
	}
	SuperBlock* superblock = (SuperBlock*)filemap;
	DWORD blockSize = superblock->BlockSize;
	DWORD* StreamDirectoryBlockMap = (DWORD*)(filemap + (ULONG_PTR)superblock->BlockMapAddr * blockSize);
	DWORD* StreamDirectory = calloc(superblock->NumDirectoryBytes, 1);
	if (StreamDirectory == NULL) {
		goto clean_viewoffile;
	}
	DWORD StreamDirectoryBlockIndex = 0;
	DWORD StreamDirectoryRemainingSize = superblock->NumDirectoryBytes;
	while (StreamDirectoryRemainingSize) {
		DWORD SizeToCopy = min(StreamDirectoryRemainingSize, blockSize);
		memcpy(
			((PBYTE)StreamDirectory) + (ULONG_PTR)StreamDirectoryBlockIndex * blockSize,
			((PBYTE)filemap) + (ULONG_PTR)blockSize * StreamDirectoryBlockMap[StreamDirectoryBlockIndex],
			SizeToCopy);
		StreamDirectoryBlockIndex++;
		StreamDirectoryRemainingSize -= SizeToCopy;
	}
	DWORD NumStreams = StreamDirectory[0];
	if (NumStreams < 2) {
		goto clean_StreamDirectory;
	}
	DWORD** StreamBlocks = calloc(NumStreams, sizeof(DWORD*));
	if (StreamBlocks == NULL) {
		goto clean_StreamDirectory;
	}
	DWORD* StreamBlocksFlat = &StreamDirectory[1 + NumStreams];
	DWORD i = 0;
	if ((1 + NumStreams) >= superblock->NumDirectoryBytes / 4) {
		goto clean_StreamBlocks;
	}
	for (DWORD stream_i = 0; stream_i < NumStreams; stream_i++) {
		DWORD StreamSize = StreamDirectory[1 + stream_i];
		DWORD StreamBlockCount = 0;
		while (StreamBlockCount * blockSize < StreamSize) {
			PVOID tmp = realloc(StreamBlocks[stream_i], ((SIZE_T)StreamBlockCount + 1) * sizeof(DWORD));
			if (tmp == NULL) {
				goto clean_StreamBlocks;
			}
			StreamBlocks[stream_i] = tmp;
			StreamBlocks[stream_i][StreamBlockCount] = StreamBlocksFlat[i];
			i++;
			StreamBlockCount++;
		}
	}
	DWORD PdbInfoStreamSize = StreamDirectory[1 + 1];
	if (PdbInfoStreamSize == 0) {
		goto clean_StreamBlocks;
	}
	PdbInfoStreamHeader* PdbInfoStream = (PdbInfoStreamHeader*)(filemap + (ULONG_PTR)StreamBlocks[1][0] * blockSize);
	guid = calloc(1, sizeof(GUID));
	if (guid == NULL) {
		goto clean_StreamBlocks;
	}
	memcpy(guid, &PdbInfoStream->UniqueId, sizeof(GUID));
clean_StreamBlocks:
	for (DWORD stream_i = 0; stream_i < NumStreams; stream_i++) {
		free(StreamBlocks[stream_i]);
	}
	free(StreamBlocks);
clean_StreamDirectory:
	free(StreamDirectory);
clean_viewoffile:
	UnmapViewOfFile(filemap);
clean_mapping:
	CloseHandle(hMapping);
clean_file:
	CloseHandle(hFile);
	return guid;
}

