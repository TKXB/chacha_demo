cmake_minimum_required(VERSION 3.9)
project(chacha)

set(CMAKE_CXX_STANDARD 11)

add_executable(demo
        chacha20-poly1305-demo.c
        poly1305-donna.c
        poly1305-donna.h
        poly1305-donna-8.h
        poly1305-donna-16.h
        poly1305-donna-32.h
        poly1305-donna-64.h
        obsolete/protypes.h
        chacha20.c
        chacha20.h
        prcpucfg.h
        prtypes.h)
