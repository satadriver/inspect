
#ifndef LOGFILE_H

#define LOGFILE_H

#include <fwpsk.h>

#define LOG_BUFFER_SIZE			(8 * 1024)
#define MIN_LOG_BUFFER_SIZE		(4 * 1024)
#define MIN_REMAINING			512

#define LOG_FILE				L"inspect.log"

#define WRITE_TO_FILE			1

#if WRITE_TO_FILE

typedef struct {
	HANDLE hFile;
	char* buf;
	SIZE_T bufsize;
	SIZE_T used;
} logfile_t;

#endif

NTSTATUS OpenLogFile(SIZE_T log_buffer_size);
void CloseLogFile();

BOOL Log(LARGE_INTEGER* system_time, const char* format, ...);
BOOL FlushLog();



#endif
