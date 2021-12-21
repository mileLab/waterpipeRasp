cmake_minimum_required(VERSION 3.16)
set(CMAKE_C_STANDART 11)
set(CMAKE_CXX_STANDARD 17)
project (waterpipe C CXX ASM)
add_executable( waterpipe 
                waterpipe.c
                aes.c
                PKSC7.c
                randomization.c)




target_sources(${PROJECT_NAME}
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/aes.c
        ${CMAKE_CURRENT_LIST_DIR}/PKSC7.c
       
    INTERFACE
       
        ${CMAKE_CURRENT_LIST_DIR}/PKSC7.h
        ${CMAKE_CURRENT_LIST_DIR}/aes.h
         ${CMAKE_CURRENT_LIST_DIR}/aes.hpp)