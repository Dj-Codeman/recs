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

typedef struct Option_bool Option_bool;

typedef struct String String;

void initialize(void);

struct Option_bool insert(struct String filename, struct String owner, struct String name);

struct Option_bool retrive(struct String owner, struct String name);

struct Option_bool remove(struct String owner, struct String name);

bool ping(struct String owner, struct String name);
