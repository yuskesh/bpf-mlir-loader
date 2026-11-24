/* abi/owned.c — before an object is closed, close the readers (ring buffer mappings) and the
 * iterators it owns. The mappings must go before the object does, and a read on an already
 * closed reader reports the STATE error kind. */
#include "abi/map_internal.h"

#include <stdlib.h>

void abi_close_owned(int64_t obj)
{
	void **v;
	abi_lock();
	size_t n = abi_handle_list_owned(H_READER, obj, &v);
	abi_unlock();
	for (size_t i = 0; i < n; i++)
		abi_reader_free(v[i]);
	free(v);
	abi_lock();
	n = abi_handle_list_owned(H_ITER, obj, &v);
	abi_unlock();
	for (size_t i = 0; i < n; i++)
		abi_iter_free(v[i]);
	free(v);
}
