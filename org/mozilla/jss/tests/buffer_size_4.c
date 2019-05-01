#include "buffer.h"
#include "assert.h"

#include <stdio.h>
#include <stdlib.h>

void test_jb(uint8_t* d) {
    j_buffer* b = jb_alloc(4);
    jb_free(b);
    b = jb_alloc(4);

    size_t r_o = 0;
    size_t w_o = 0;

    int i_r = 0;
    size_t s_r = 0;
    uint8_t* r_b = calloc(9, sizeof(uint8_t));

    printf("Testing get+put\n");
    // pc=0 gc=0


    // pc=0 gc=1
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // pc=0 gc=2
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // pc=0 gc=3
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // pc=0 gc=4
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // pc=0 gc=5
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // pc=1 gc=0
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }



    // pc=1 gc=1
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // pc=1 gc=2
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // pc=1 gc=3
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // pc=1 gc=4
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // pc=1 gc=5
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // pc=2 gc=0
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }



    // pc=2 gc=1
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // pc=2 gc=2
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // pc=2 gc=3
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // pc=2 gc=4
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // pc=2 gc=5
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // pc=3 gc=0
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }



    // pc=3 gc=1
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // pc=3 gc=2
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // pc=3 gc=3
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // pc=3 gc=4
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // pc=3 gc=5
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // pc=4 gc=0
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }



    // pc=4 gc=1
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // pc=4 gc=2
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // pc=4 gc=3
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // pc=4 gc=4
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // pc=4 gc=5
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // pc=5 gc=0
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }



    // pc=5 gc=1
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // pc=5 gc=2
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // pc=5 gc=3
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // pc=5 gc=4
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // pc=5 gc=5
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    printf("Testing write+get\n");
    // ws=0 gc=0
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 0);
    if (s_r != 0) {
        assert(s_r <= 0);
        w_o += s_r;
    }



    // ws=0 gc=1
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 0);
    if (s_r != 0) {
        assert(s_r <= 0);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // ws=0 gc=2
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 0);
    if (s_r != 0) {
        assert(s_r <= 0);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // ws=0 gc=3
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 0);
    if (s_r != 0) {
        assert(s_r <= 0);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // ws=0 gc=4
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 0);
    if (s_r != 0) {
        assert(s_r <= 0);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // ws=0 gc=5
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 0);
    if (s_r != 0) {
        assert(s_r <= 0);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // ws=1 gc=0
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 1);
    if (s_r != 0) {
        assert(s_r <= 1);
        w_o += s_r;
    }



    // ws=1 gc=1
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 1);
    if (s_r != 0) {
        assert(s_r <= 1);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // ws=1 gc=2
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 1);
    if (s_r != 0) {
        assert(s_r <= 1);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // ws=1 gc=3
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 1);
    if (s_r != 0) {
        assert(s_r <= 1);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // ws=1 gc=4
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 1);
    if (s_r != 0) {
        assert(s_r <= 1);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // ws=1 gc=5
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 1);
    if (s_r != 0) {
        assert(s_r <= 1);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // ws=2 gc=0
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 2);
    if (s_r != 0) {
        assert(s_r <= 2);
        w_o += s_r;
    }



    // ws=2 gc=1
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 2);
    if (s_r != 0) {
        assert(s_r <= 2);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // ws=2 gc=2
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 2);
    if (s_r != 0) {
        assert(s_r <= 2);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // ws=2 gc=3
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 2);
    if (s_r != 0) {
        assert(s_r <= 2);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // ws=2 gc=4
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 2);
    if (s_r != 0) {
        assert(s_r <= 2);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // ws=2 gc=5
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 2);
    if (s_r != 0) {
        assert(s_r <= 2);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // ws=3 gc=0
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 3);
    if (s_r != 0) {
        assert(s_r <= 3);
        w_o += s_r;
    }



    // ws=3 gc=1
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 3);
    if (s_r != 0) {
        assert(s_r <= 3);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // ws=3 gc=2
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 3);
    if (s_r != 0) {
        assert(s_r <= 3);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // ws=3 gc=3
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 3);
    if (s_r != 0) {
        assert(s_r <= 3);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // ws=3 gc=4
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 3);
    if (s_r != 0) {
        assert(s_r <= 3);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // ws=3 gc=5
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 3);
    if (s_r != 0) {
        assert(s_r <= 3);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // ws=4 gc=0
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 4);
    if (s_r != 0) {
        assert(s_r <= 4);
        w_o += s_r;
    }



    // ws=4 gc=1
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 4);
    if (s_r != 0) {
        assert(s_r <= 4);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // ws=4 gc=2
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 4);
    if (s_r != 0) {
        assert(s_r <= 4);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // ws=4 gc=3
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 4);
    if (s_r != 0) {
        assert(s_r <= 4);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // ws=4 gc=4
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 4);
    if (s_r != 0) {
        assert(s_r <= 4);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // ws=4 gc=5
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 4);
    if (s_r != 0) {
        assert(s_r <= 4);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // ws=5 gc=0
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 5);
    if (s_r != 0) {
        assert(s_r <= 5);
        w_o += s_r;
    }



    // ws=5 gc=1
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 5);
    if (s_r != 0) {
        assert(s_r <= 5);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // ws=5 gc=2
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 5);
    if (s_r != 0) {
        assert(s_r <= 5);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // ws=5 gc=3
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 5);
    if (s_r != 0) {
        assert(s_r <= 5);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // ws=5 gc=4
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 5);
    if (s_r != 0) {
        assert(s_r <= 5);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    // ws=5 gc=5
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 5);
    if (s_r != 0) {
        assert(s_r <= 5);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_get(b);
    if (i_r != EOF) {
        assert(((uint8_t)i_r) == ((uint8_t)d[r_o]));
        r_o += 1;
    }



    printf("Testing put+read\n");
    // pc=0 rs=0
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 0);
    if (s_r != 0) {
        assert(s_r <= 0);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // pc=0 rs=1
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 1);
    if (s_r != 0) {
        assert(s_r <= 1);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // pc=0 rs=2
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 2);
    if (s_r != 0) {
        assert(s_r <= 2);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // pc=0 rs=3
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 3);
    if (s_r != 0) {
        assert(s_r <= 3);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // pc=0 rs=4
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 4);
    if (s_r != 0) {
        assert(s_r <= 4);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // pc=0 rs=5
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 5);
    if (s_r != 0) {
        assert(s_r <= 5);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // pc=1 rs=0
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 0);
    if (s_r != 0) {
        assert(s_r <= 0);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // pc=1 rs=1
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 1);
    if (s_r != 0) {
        assert(s_r <= 1);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // pc=1 rs=2
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 2);
    if (s_r != 0) {
        assert(s_r <= 2);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // pc=1 rs=3
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 3);
    if (s_r != 0) {
        assert(s_r <= 3);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // pc=1 rs=4
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 4);
    if (s_r != 0) {
        assert(s_r <= 4);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // pc=1 rs=5
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 5);
    if (s_r != 0) {
        assert(s_r <= 5);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // pc=2 rs=0
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 0);
    if (s_r != 0) {
        assert(s_r <= 0);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // pc=2 rs=1
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 1);
    if (s_r != 0) {
        assert(s_r <= 1);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // pc=2 rs=2
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 2);
    if (s_r != 0) {
        assert(s_r <= 2);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // pc=2 rs=3
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 3);
    if (s_r != 0) {
        assert(s_r <= 3);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // pc=2 rs=4
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 4);
    if (s_r != 0) {
        assert(s_r <= 4);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // pc=2 rs=5
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 5);
    if (s_r != 0) {
        assert(s_r <= 5);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // pc=3 rs=0
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 0);
    if (s_r != 0) {
        assert(s_r <= 0);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // pc=3 rs=1
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 1);
    if (s_r != 0) {
        assert(s_r <= 1);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // pc=3 rs=2
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 2);
    if (s_r != 0) {
        assert(s_r <= 2);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // pc=3 rs=3
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 3);
    if (s_r != 0) {
        assert(s_r <= 3);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // pc=3 rs=4
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 4);
    if (s_r != 0) {
        assert(s_r <= 4);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // pc=3 rs=5
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 5);
    if (s_r != 0) {
        assert(s_r <= 5);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // pc=4 rs=0
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 0);
    if (s_r != 0) {
        assert(s_r <= 0);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // pc=4 rs=1
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 1);
    if (s_r != 0) {
        assert(s_r <= 1);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // pc=4 rs=2
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 2);
    if (s_r != 0) {
        assert(s_r <= 2);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // pc=4 rs=3
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 3);
    if (s_r != 0) {
        assert(s_r <= 3);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // pc=4 rs=4
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 4);
    if (s_r != 0) {
        assert(s_r <= 4);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // pc=4 rs=5
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 5);
    if (s_r != 0) {
        assert(s_r <= 5);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // pc=5 rs=0
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 0);
    if (s_r != 0) {
        assert(s_r <= 0);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // pc=5 rs=1
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 1);
    if (s_r != 0) {
        assert(s_r <= 1);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // pc=5 rs=2
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 2);
    if (s_r != 0) {
        assert(s_r <= 2);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // pc=5 rs=3
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 3);
    if (s_r != 0) {
        assert(s_r <= 3);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // pc=5 rs=4
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 4);
    if (s_r != 0) {
        assert(s_r <= 4);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // pc=5 rs=5
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    i_r = jb_put(b, d[w_o]);
    if (i_r != EOF) {
        w_o += 1;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 5);
    if (s_r != 0) {
        assert(s_r <= 5);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    printf("Testing write+read\n");
    // ws=0 rs=0
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 0);
    if (s_r != 0) {
        assert(s_r <= 0);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 0);
    if (s_r != 0) {
        assert(s_r <= 0);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // ws=0 rs=1
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 0);
    if (s_r != 0) {
        assert(s_r <= 0);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 1);
    if (s_r != 0) {
        assert(s_r <= 1);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // ws=0 rs=2
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 0);
    if (s_r != 0) {
        assert(s_r <= 0);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 2);
    if (s_r != 0) {
        assert(s_r <= 2);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // ws=0 rs=3
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 0);
    if (s_r != 0) {
        assert(s_r <= 0);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 3);
    if (s_r != 0) {
        assert(s_r <= 3);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // ws=0 rs=4
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 0);
    if (s_r != 0) {
        assert(s_r <= 0);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 4);
    if (s_r != 0) {
        assert(s_r <= 4);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // ws=0 rs=5
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 0);
    if (s_r != 0) {
        assert(s_r <= 0);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 5);
    if (s_r != 0) {
        assert(s_r <= 5);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // ws=1 rs=0
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 1);
    if (s_r != 0) {
        assert(s_r <= 1);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 0);
    if (s_r != 0) {
        assert(s_r <= 0);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // ws=1 rs=1
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 1);
    if (s_r != 0) {
        assert(s_r <= 1);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 1);
    if (s_r != 0) {
        assert(s_r <= 1);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // ws=1 rs=2
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 1);
    if (s_r != 0) {
        assert(s_r <= 1);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 2);
    if (s_r != 0) {
        assert(s_r <= 2);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // ws=1 rs=3
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 1);
    if (s_r != 0) {
        assert(s_r <= 1);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 3);
    if (s_r != 0) {
        assert(s_r <= 3);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // ws=1 rs=4
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 1);
    if (s_r != 0) {
        assert(s_r <= 1);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 4);
    if (s_r != 0) {
        assert(s_r <= 4);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // ws=1 rs=5
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 1);
    if (s_r != 0) {
        assert(s_r <= 1);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 5);
    if (s_r != 0) {
        assert(s_r <= 5);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // ws=2 rs=0
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 2);
    if (s_r != 0) {
        assert(s_r <= 2);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 0);
    if (s_r != 0) {
        assert(s_r <= 0);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // ws=2 rs=1
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 2);
    if (s_r != 0) {
        assert(s_r <= 2);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 1);
    if (s_r != 0) {
        assert(s_r <= 1);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // ws=2 rs=2
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 2);
    if (s_r != 0) {
        assert(s_r <= 2);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 2);
    if (s_r != 0) {
        assert(s_r <= 2);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // ws=2 rs=3
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 2);
    if (s_r != 0) {
        assert(s_r <= 2);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 3);
    if (s_r != 0) {
        assert(s_r <= 3);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // ws=2 rs=4
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 2);
    if (s_r != 0) {
        assert(s_r <= 2);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 4);
    if (s_r != 0) {
        assert(s_r <= 4);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // ws=2 rs=5
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 2);
    if (s_r != 0) {
        assert(s_r <= 2);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 5);
    if (s_r != 0) {
        assert(s_r <= 5);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // ws=3 rs=0
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 3);
    if (s_r != 0) {
        assert(s_r <= 3);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 0);
    if (s_r != 0) {
        assert(s_r <= 0);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // ws=3 rs=1
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 3);
    if (s_r != 0) {
        assert(s_r <= 3);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 1);
    if (s_r != 0) {
        assert(s_r <= 1);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // ws=3 rs=2
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 3);
    if (s_r != 0) {
        assert(s_r <= 3);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 2);
    if (s_r != 0) {
        assert(s_r <= 2);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // ws=3 rs=3
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 3);
    if (s_r != 0) {
        assert(s_r <= 3);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 3);
    if (s_r != 0) {
        assert(s_r <= 3);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // ws=3 rs=4
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 3);
    if (s_r != 0) {
        assert(s_r <= 3);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 4);
    if (s_r != 0) {
        assert(s_r <= 4);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // ws=3 rs=5
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 3);
    if (s_r != 0) {
        assert(s_r <= 3);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 5);
    if (s_r != 0) {
        assert(s_r <= 5);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // ws=4 rs=0
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 4);
    if (s_r != 0) {
        assert(s_r <= 4);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 0);
    if (s_r != 0) {
        assert(s_r <= 0);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // ws=4 rs=1
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 4);
    if (s_r != 0) {
        assert(s_r <= 4);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 1);
    if (s_r != 0) {
        assert(s_r <= 1);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // ws=4 rs=2
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 4);
    if (s_r != 0) {
        assert(s_r <= 4);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 2);
    if (s_r != 0) {
        assert(s_r <= 2);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // ws=4 rs=3
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 4);
    if (s_r != 0) {
        assert(s_r <= 4);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 3);
    if (s_r != 0) {
        assert(s_r <= 3);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // ws=4 rs=4
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 4);
    if (s_r != 0) {
        assert(s_r <= 4);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 4);
    if (s_r != 0) {
        assert(s_r <= 4);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // ws=4 rs=5
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 4);
    if (s_r != 0) {
        assert(s_r <= 4);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 5);
    if (s_r != 0) {
        assert(s_r <= 5);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // ws=5 rs=0
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 5);
    if (s_r != 0) {
        assert(s_r <= 5);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 0);
    if (s_r != 0) {
        assert(s_r <= 0);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // ws=5 rs=1
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 5);
    if (s_r != 0) {
        assert(s_r <= 5);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 1);
    if (s_r != 0) {
        assert(s_r <= 1);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // ws=5 rs=2
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 5);
    if (s_r != 0) {
        assert(s_r <= 5);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 2);
    if (s_r != 0) {
        assert(s_r <= 2);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // ws=5 rs=3
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 5);
    if (s_r != 0) {
        assert(s_r <= 5);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 3);
    if (s_r != 0) {
        assert(s_r <= 3);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // ws=5 rs=4
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 5);
    if (s_r != 0) {
        assert(s_r <= 5);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 4);
    if (s_r != 0) {
        assert(s_r <= 4);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



    // ws=5 rs=5
    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_write(b, d + w_o, 5);
    if (s_r != 0) {
        assert(s_r <= 5);
        w_o += s_r;
    }

    assert(r_o <= w_o);
    assert((r_o < w_o) == jb_can_read(b));
    assert((w_o - r_o) <= 4);
    assert(((w_o - r_o) < 4) == jb_can_write(b));
    s_r = jb_read(b, r_b, 5);
    if (s_r != 0) {
        assert(s_r <= 5);
        for (size_t i = 0; i < s_r; i++) {
            assert(d[r_o] == r_b[i]);
            r_o += 1;
        }
    }



}

int main() {
    uint8_t* d = (uint8_t*)"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrs";
    test_jb(d);
    return 0;
}
