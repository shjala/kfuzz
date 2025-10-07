/*
 * Copyright (c) 2025 Shahriyar Jalayeri <shahriyar@posteo.de>
 * All rights reserved.
 */

#include "kflog.h"

int _g_seed_init = 0;
/* external results */
unsigned long int _g_randrsl[256], _g_randcnt;

/* internal state */
static unsigned long int mm[256];
static unsigned long int aa = 0, bb = 0, cc = 0;


void isaac()
{
    register unsigned long int i, x, y;

    cc = cc + 1;    /* cc just gets incremented once per 256 results */
    bb = bb + cc;   /* then combined with bb */

    for (i = 0; i<256; ++i)
    {
        x = mm[i];
        switch (i % 4)
        {
        case 0: aa = aa ^ (aa << 13); break;
        case 1: aa = aa ^ (aa >> 6); break;
        case 2: aa = aa ^ (aa << 2); break;
        case 3: aa = aa ^ (aa >> 16); break;
        }
        aa = mm[(i + 128) % 256] + aa;
        mm[i] = y = mm[(x >> 2) % 256] + aa + bb;
        _g_randrsl[i] = bb = mm[(y >> 10) % 256] + x;

        /* Note that bits 2..9 are chosen from x but 10..17 are chosen
        from y.  The only important thing here is that 2..9 and 10..17
        don't overlap.  2..9 and 10..17 were then chosen for speed in
        the optimized version (rand.c) */
        /* See http://burtleburtle.net/bob/rand/isaac.html
        for further explanations and analysis. */
    }
}


/* if (flag!=0), then use the contents of randrsl[] to initialize mm[]. */
#define mix(a,b,c,d,e,f,g,h) \
{ \
    a ^= b << 11; d += a; b += c; \
    b ^= c >> 2;  e += b; c += d; \
    c ^= d << 8;  f += c; d += e; \
    d ^= e >> 16; g += d; e += f; \
    e ^= f << 10; h += e; f += g; \
    f ^= g >> 4;  a += f; g += h; \
    g ^= h << 8;  b += g; h += a; \
    h ^= a >> 9;  c += h; a += b; \
}

void randinit(int flag)
{
    int i;
    unsigned long int a, b, c, d, e, f, g, h;
    aa = bb = cc = 0;
    a = b = c = d = e = f = g = h = 0x9e3779b9;  /* the golden ratio */

    for (i = 0; i<4; ++i)          /* scramble it */
    {
        mix(a, b, c, d, e, f, g, h);
    }

    for (i = 0; i<256; i += 8)   /* fill in mm[] with messy stuff */
    {
        if (flag)                  /* use all the information in the seed */
        {
            a += _g_randrsl[i]; b += _g_randrsl[i + 1]; c += _g_randrsl[i + 2]; d += _g_randrsl[i + 3];
            e += _g_randrsl[i + 4]; f += _g_randrsl[i + 5]; g += _g_randrsl[i + 6]; h += _g_randrsl[i + 7];
        }
        mix(a, b, c, d, e, f, g, h);
        mm[i] = a; mm[i + 1] = b; mm[i + 2] = c; mm[i + 3] = d;
        mm[i + 4] = e; mm[i + 5] = f; mm[i + 6] = g; mm[i + 7] = h;
    }

    if (flag)
    {        /* do a second pass to make all of the seed affect all of mm */
        for (i = 0; i<256; i += 8)
        {
            a += mm[i]; b += mm[i + 1]; c += mm[i + 2]; d += mm[i + 3];
            e += mm[i + 4]; f += mm[i + 5]; g += mm[i + 6]; h += mm[i + 7];
            mix(a, b, c, d, e, f, g, h);
            mm[i] = a; mm[i + 1] = b; mm[i + 2] = c; mm[i + 3] = d;
            mm[i + 4] = e; mm[i + 5] = f; mm[i + 6] = g; mm[i + 7] = h;
        }
    }

    isaac();            /* fill in the first set of results */
    _g_randcnt = 256;   /* prepare to use the first set of results */
}


void isaac_get_prng(char* buffer, unsigned int size)
{
    unsigned long int i, filled = 0, remaining = size;

    if (_g_seed_init == 0)
    {
        
#if defined(__RAND_PRNG_SEED)
        LARGE_INTEGER p = KeQueryPerformanceCounter(NULL);
        aa = bb = cc = (unsigned long int)0;
        for (i = 0; i < 256; ++i) mm[i] = _g_randrsl[i] = (unsigned long int)p.QuadPart;
#else
        aa = bb = cc = (unsigned long int)0;
        for (i = 0; i < 256; ++i) mm[i] = _g_randrsl[i] = (unsigned long int)0x9e3779b9;
#endif
        _g_seed_init = 1;
    }

    randinit(1);

    for (i = 0; i < (ROUND_UP(size, 256) / 256); ++i)
    {
        isaac();
        if (remaining < 256)
        {
            memcpy(buffer + filled, _g_randrsl, remaining);
            return;
        }
        else
        {
            memcpy((buffer + filled), _g_randrsl, 256);
            filled += 256;
            remaining -= 256;
        }
    }
}


ULONG
GetRandomInt(
    VOID
    )
{
    ULONG uRandom = 0;

    isaac_get_prng((char *)&uRandom, sizeof(ULONG));
    if (uRandom == 0)
        uRandom = 1;

    return uRandom;
}