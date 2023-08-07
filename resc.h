#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define DEBUG false

#define STREAMING_BUFFER_SIZE 102400.00

#define SOFT_MOVE_FILES false

#define LEAVE_IN_PEACE false

#define ARRAY_LEN 80963

#define CHUNK_SIZE 16

void initialize(void);

bool insert(const char *unsafe_filename, const char *unsafe_owner, const char *unsafe_name);

bool retrive(const char *unsafe_owner, const char *unsafe_name);

bool remove(const char *unsafe_owner, const char *unsafe_name);

bool ping(const char *unsafe_owner, const char *unsafe_name);

bool check_map(uint32_t map_num);

bool update_map(uint32_t map_num);
