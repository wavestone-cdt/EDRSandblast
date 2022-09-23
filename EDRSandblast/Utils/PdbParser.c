#include <Windows.h>

// Written from information found here: https://llvm.org/docs/PDB/index.html

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
	HANDLE hMapping = NULL;
	PBYTE filemap = NULL;
	DWORD* StreamDirectory = NULL;
	DWORD** StreamBlocks = NULL;
	DWORD NumStreams = 0;

    HANDLE hFile = CreateFileW(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return NULL;
	}
    hMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hMapping == NULL) {
		goto clean;
	}
    filemap = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
	if (filemap == NULL) {
		goto clean;
	}
	SuperBlock* superblock = (SuperBlock*)filemap;
	DWORD blockSize = superblock->BlockSize;
	DWORD* StreamDirectoryBlockMap = (DWORD*)(filemap + (ULONG_PTR)superblock->BlockMapAddr * blockSize);
	StreamDirectory = calloc(superblock->NumDirectoryBytes, 1);
	if (StreamDirectory == NULL) {
		goto clean;
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
	NumStreams = StreamDirectory[0];
	if (NumStreams < 2) {
		NumStreams = 0;
		goto clean;
	}
	StreamBlocks = calloc(NumStreams, sizeof(DWORD*));
	if (StreamBlocks == NULL) {
		goto clean;
	}
	DWORD* StreamBlocksFlat = &StreamDirectory[1 + NumStreams];
	DWORD i = 0;
	if ((1 + NumStreams) >= superblock->NumDirectoryBytes / 4) {
		goto clean;
	}
	for (DWORD stream_i = 0; stream_i < NumStreams; stream_i++) {
		DWORD StreamSize = StreamDirectory[1 + stream_i];
		DWORD StreamBlockCount = 0;
		while (StreamBlockCount * blockSize < StreamSize) {
			PVOID tmp = realloc(StreamBlocks[stream_i], ((SIZE_T)StreamBlockCount + 1) * sizeof(DWORD));
			if (tmp == NULL) {
				goto clean;
			}
			StreamBlocks[stream_i] = tmp;
			StreamBlocks[stream_i][StreamBlockCount] = StreamBlocksFlat[i];
			i++;
			StreamBlockCount++;
		}
	}
	DWORD PdbInfoStreamSize = StreamDirectory[1 + 1];
	if (PdbInfoStreamSize == 0) {
		goto clean;
	}
	PdbInfoStreamHeader* PdbInfoStream = (PdbInfoStreamHeader*)(filemap + (ULONG_PTR)StreamBlocks[1][0] * blockSize);
	guid = calloc(1, sizeof(GUID));
	if (guid == NULL) {
		goto clean;
	}
	memcpy(guid, &PdbInfoStream->UniqueId, sizeof(GUID));
clean:
	if (StreamBlocks) {
		for (DWORD stream_i = 0; stream_i < NumStreams; stream_i++) {
#pragma warning(disable : 6001) //compiler analysis is wrong for some reason (or maybe I am)
			if (StreamBlocks[stream_i]) {
#pragma warning(default: 6001)
				free(StreamBlocks[stream_i]);
			}
		}
		free(StreamBlocks);
	}
	if (StreamDirectory) {
		free(StreamDirectory);
	}
	if (filemap) {
		UnmapViewOfFile(filemap);
	}
	if (hMapping != NULL) {
		CloseHandle(hMapping);
	}
	if (hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
	}
	return guid;
}

