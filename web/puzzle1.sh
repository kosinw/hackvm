#!/bin/bash

sudo docker run --rm -v $(pwd):/src -u $(id -u):$(id -g) \
    emscripten/emsdk emcc -O2 -DNDEBUG -sALLOW_MEMORY_GROWTH -sTOTAL_MEMORY=134414336 -sNO_EXIT_RUNTIME=1 \
    -sFORCE_FILESYSTEM=1 --embed-file build/puzzle1 --pre-js web/prelude1.js \
    -o web/vm-core-1.js vm.c