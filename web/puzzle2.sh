#!/bin/bash

sudo docker run --rm -v $(pwd):/src -u $(id -u):$(id -g) \
    emscripten/emsdk emcc -O2 -DNDEBUG -sALLOW_MEMORY_GROWTH -sTOTAL_MEMORY=134414336 -sNO_EXIT_RUNTIME=1 \
    -sFORCE_FILESYSTEM=1 --embed-file build/puzzle2 --pre-js web/prelude2.js \
    -o web/vm-core-2.js vm.c