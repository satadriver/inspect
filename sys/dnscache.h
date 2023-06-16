#ifndef DNS_CACHE_H
#define DNS_CACHE_H


#include <fwpsk.h>


#define MAX_BINS            32

#define HOST_NAME_MIN_LEN   8
#define HOST_NAME_MAX_LEN   255






BOOL InitDnsCache(unsigned nbuckets, unsigned max);
void FreeDnsCache();

BOOL AddIPv4ToDnsCache(const UINT8* ipv4,
	const char* hostname,
	UINT16 hostnamelen);

BOOL AddIPv6ToDnsCache(const UINT8* ipv6,
	const char* hostname,
	UINT16 hostnamelen);

const char* GetIPv4FromDnsCache(const UINT8* ipv4, char* hostname);
const char* GetIPv6FromDnsCache(const UINT8* ipv6, char* hostname);



/* http://burtleburtle.net/bob/hash/doobs.html */
#define mix(a, b, c)                      \
        {                                 \
          a -= b; a -= c; a ^= (c >> 13); \
          b -= c; b -= a; b ^= (a << 8);  \
          c -= a; c -= b; c ^= (b >> 13); \
          a -= b; a -= c; a ^= (c >> 12); \
          b -= c; b -= a; b ^= (a << 16); \
          c -= a; c -= b; c ^= (b >> 5);  \
          a -= b; a -= c; a ^= (c >> 3);  \
          b -= c; b -= a; b ^= (a << 10); \
          c -= a; c -= b; c ^= (b >> 15); \
        }

typedef struct page_t {
	struct page_t* next;
	int free;

	char data[1];
} page_t;

typedef struct {
	page_t* page;
	unsigned off;
	UINT16 len;
} hostname_t;

typedef struct cache_header_t {
	struct cache_header_t* prev;
	struct cache_header_t* next;
} cache_header_t;

typedef struct cache_time_t {
	void* unused1;
	void* unused2;

	struct cache_time_t* older;
	struct cache_time_t* newer;
} cache_time_t;

typedef struct cache_entry_t {
	struct cache_entry_t* prev;
	struct cache_entry_t* next;

	struct cache_entry_t* newer;
	struct cache_entry_t* older;

	hostname_t hostname;
	UINT8 ip[1];
} cache_entry_t;

typedef struct {
	cache_header_t* buckets;
	cache_entry_t* entries;
	cache_entry_t* free;
	cache_time_t time;
	unsigned nbuckets;

	page_t* bins[MAX_BINS];

	UINT32(*hash)(const UINT8* ip, unsigned max);
} dns_cache_t;

static dns_cache_t ipv4_cache;
static dns_cache_t ipv6_cache;

static UINT16 bins_max_len[MAX_BINS];
static UINT8 bucket_indices[HOST_NAME_MAX_LEN + 1];

static BOOL InitCache(dns_cache_t* ip_cache,
	unsigned nbuckets,
	unsigned max,
	SIZE_T ip_size);

static void FreeCache(dns_cache_t* ip_cache);

static BOOL AddIPToDnsCache(dns_cache_t* ip_cache,
	const UINT8* ip,
	SIZE_T ip_size,
	const char* hostname,
	UINT16 hostnamelen);

static const char* GetIPFromDnsCache(dns_cache_t* ip_cache,
	const UINT8* ip,
	SIZE_T ip_size,
	char* hostname);

static void TouchCacheEntry(dns_cache_t* ip_cache,
	cache_header_t* header,
	cache_entry_t* entry);

__inline static void UnlinkCacheEntry(cache_entry_t* entry)
{
	entry->prev->next = entry->next;
	entry->next->prev = entry->prev;
}

static void MakeCacheEntryNewest(dns_cache_t* ip_cache, cache_entry_t* entry);

static BOOL SaveHost(dns_cache_t* ip_cache,
	unsigned bin,
	const char* hostname,
	UINT16 hostnamelen,
	page_t** page,
	unsigned* off);

static void RemoveFromPage(hostname_t* host);
static void FreeBin(page_t* page);
static UINT32 HashIPv4(const UINT8* ip, unsigned nbuckets);
static UINT32 HashIPv6(const UINT8* ip, unsigned nbuckets);

#endif /* DNS_CACHE_H */
