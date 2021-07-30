#define FILE_VIEW 0
#define MEMORY_VIEW 1

#ifdef _WIN64
	#if FILE_VIEW
		#include "FileViewerX64.cpp"
	#else
		#include "MemoryViewerX64.cpp"
	#endif
#else
	#if FILE_VIEW
		#include "FileViewerX86.cpp"
	#else
		#include "MemoryViewerX86.cpp"
	#endif
#endif