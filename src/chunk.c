
#include "s_server.h"

#define MB (1024 * 1024)
int chunkLowMark = 0, chunkCriticalMark = 0, chunkHighMark = 0;

void preinitChunks()
{
	CONFIG_VARIABLE(chunkLowMark, CONFIG_INT,
			"Low mark for chunk memory (0 = auto).");
	CONFIG_VARIABLE(chunkCriticalMark, CONFIG_INT,
			"Critical mark for chunk memory (0 = auto).");
	CONFIG_VARIABLE(chunkHighMark, CONFIG_INT,
			"High mark for chunk memory.");
}

static void initChunksCommon()
{
#define ROUND_CHUNKS(a) a = (((a) + CHUNK_SIZE - 1) / CHUNK_SIZE) * CHUNK_SIZE;
	int q;

	if (CHUNK_SIZE != 1 << log2_ceil(CHUNK_SIZE)) {
		do_log(L_ERROR, "CHUNK SIZE %d is not a power of two.\n",
		       CHUNK_SIZE);
		exit(1);
	}

	ROUND_CHUNKS(chunkHighMark);
	ROUND_CHUNKS(chunkCriticalMark);
	ROUND_CHUNKS(chunkLowMark);

	if (chunkHighMark < 8 * CHUNK_SIZE) {
		int mem = physicalMemory();
		if (mem > 0)
			chunkHighMark = mem / 4;
		else
			chunkHighMark = 24 * MB;
		chunkHighMark = MIN(chunkHighMark, 24 * MB);
		chunkHighMark = MAX(chunkHighMark, 8 * CHUNK_SIZE);
	}

	if (chunkHighMark < MB / 2)
		fprintf(stderr,
			"Warning: little chunk memory (%d bytes)\n",
			chunkHighMark);

	q = 0;
	if (chunkLowMark <= 0)
		q = 1;
	if (chunkLowMark < 4 * CHUNK_SIZE ||
	    chunkLowMark > chunkHighMark - 4 * CHUNK_SIZE) {
		chunkLowMark = MIN(chunkHighMark - 4 * CHUNK_SIZE,
				   chunkHighMark * 3 / 4);
		ROUND_CHUNKS(chunkLowMark);
		if (!q)
			do_log(L_WARN,
			       "Inconsistent chunkLowMark -- setting to %d.\n",
			       chunkLowMark);
	}

	q = 0;
	if (chunkCriticalMark <= 0)
		q = 1;
	if (chunkCriticalMark >= chunkHighMark - 2 * CHUNK_SIZE ||
	    chunkCriticalMark <= chunkLowMark + 2 * CHUNK_SIZE) {
		chunkCriticalMark =
		    MIN(chunkHighMark - 2 * CHUNK_SIZE,
			chunkLowMark + (chunkHighMark -
					chunkLowMark) * 15 / 16);
		ROUND_CHUNKS(chunkCriticalMark);
		if (!q)
			do_log(L_WARN, "Inconsistent chunkCriticalMark -- "
			       "setting to %d.\n", chunkCriticalMark);
	}
#undef ROUND_CHUNKS
}

int used_chunks = 0;

static void maybe_free_chunks(int arenas, int force)
{
	if (force || used_chunks >= CHUNKS(chunkHighMark)) {
		discardObjects(force, force);
	}

	if (arenas)
		free_chunk_arenas();

	if (used_chunks >= CHUNKS(chunkLowMark) && !objectExpiryScheduled) {
		TimeEventHandlerPtr event;
		event = scheduleTimeEvent(1, discardObjectsHandler, 0, NULL);
		if (event)
			objectExpiryScheduled = 1;
	}
}

void initChunks(void)
{
	used_chunks = 0;
	initChunksCommon();
}

void free_chunk_arenas()
{
	return;
}

void *get_chunk()
{
	void *chunk;

	if (used_chunks > CHUNKS(chunkHighMark))
		maybe_free_chunks(0, 0);
	if (used_chunks > CHUNKS(chunkHighMark))
		return NULL;
	chunk = malloc(CHUNK_SIZE);
	if (!chunk) {
		maybe_free_chunks(1, 1);
		chunk = malloc(CHUNK_SIZE);
		if (!chunk)
			return NULL;
	}
	used_chunks++;
	return chunk;
}

void *maybe_get_chunk()
{
	void *chunk;
	if (used_chunks > CHUNKS(chunkHighMark))
		return NULL;
	chunk = malloc(CHUNK_SIZE);
	if (chunk)
		used_chunks++;
	return chunk;
}

void dispose_chunk(void *chunk)
{
	assert(chunk != NULL);
	free(chunk);
	used_chunks--;
}

void free_chunks()
{
	return;
}

int totalChunkArenaSize()
{
	return used_chunks * CHUNK_SIZE;
}
