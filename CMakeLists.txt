
cmake_minimum_required(VERSION 3.1)
project(aws-c-auth C)

if (POLICY CMP0069)
    cmake_policy(SET CMP0069 NEW) # Enable LTO/IPO if available in the compiler, see AwsCFlags
endif()

if (DEFINED CMAKE_PREFIX_PATH)
    file(TO_CMAKE_PATH "${CMAKE_PREFIX_PATH}" CMAKE_PREFIX_PATH)
endif()

if (DEFINED CMAKE_INSTALL_PREFIX)
    file(TO_CMAKE_PATH "${CMAKE_INSTALL_PREFIX}" CMAKE_INSTALL_PREFIX)
endif()


if (UNIX AND NOT APPLE)
    include(GNUInstallDirs)
elseif(NOT DEFINED CMAKE_INSTALL_LIBDIR)
    set(CMAKE_INSTALL_LIBDIR "lib")
endif()

# This is required in order to append /lib/cmake to each element in CMAKE_PREFIX_PATH
set(AWS_MODULE_DIR "/${CMAKE_INSTALL_LIBDIR}/cmake")
string(REPLACE ";" "${AWS_MODULE_DIR};" AWS_MODULE_PATH "${CMAKE_PREFIX_PATH}${AWS_MODULE_DIR}")
# Append that generated list to the module search path
list(APPEND CMAKE_MODULE_PATH ${AWS_MODULE_PATH})

include(AwsCFlags)
include(AwsCheckHeaders)
include(AwsSharedLibSetup)
include(AwsSanitizers)
include(AwsFindPackage)

option(BUILD_RELOCATABLE_BINARIES
        "Build Relocatable Binaries, this will turn off features that will fail on older kernels than used for the build."
        OFF)

file(GLOB AWS_AUTH_ROOT_HEADERS
        "include/aws/auth/*.h"
        )

file(GLOB AWS_AUTH_PRIVATE_HEADERS
        "include/aws/auth/private/*.h"
        )

file(GLOB AWS_AUTH_ROOT_SRC
        "source/*.c"
        )

if (WIN32)
    if (MSVC)
        source_group("Header Files\\aws\\auth" FILES ${AWS_AUTH_HEADERS})
        source_group("Source Files" FILES ${AWS_AUTH_SRC})
    endif ()
    set(PLATFORM_LIBS "")
elseif (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(PLATFORM_LIBS "")
elseif (APPLE)
    set(PLATFORM_LIBS "")
elseif (CMAKE_SYSTEM_NAME STREQUAL "FreeBSD" OR CMAKE_SYSTEM_NAME STREQUAL "NetBSD")
    set(PLATFORM_LIBS "")
endif()

file(GLOB AUTH_HEADERS
        ${AWS_AUTH_ROOT_HEADERS}
        ${AWS_AUTH_PRIVATE_HEADERS}
        )

file(GLOB AUTH_SRC
        ${AWS_AUTH_ROOT_SRC}
        )

add_library(${PROJECT_NAME} ${LIBTYPE} ${AUTH_HEADERS} ${AUTH_SRC})
aws_set_common_properties(${PROJECT_NAME})
aws_prepare_symbol_visibility_args(${PROJECT_NAME} "AWS_AUTH")
aws_check_headers(${PROJECT_NAME} ${AWS_AUTH_ROOT_HEADERS})

aws_add_sanitizers(${PROJECT_NAME})

# We are not ABI stable yet
set_target_properties(${PROJECT_NAME} PROPERTIES VERSION 1.0.0)

target_compile_definitions(${PROJECT_NAME} PRIVATE -DCJSON_HIDE_SYMBOLS)

if (BUILD_RELOCATABLE_BINARIES)
    target_compile_definitions(${PROJECT_NAME} PRIVATE "-DCOMPAT_MODE")
endif()

target_include_directories(${PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>)

aws_use_package(aws-c-sdkutils)
aws_use_package(aws-c-cal)
aws_use_package(aws-c-http)

target_link_libraries(${PROJECT_NAME} PUBLIC ${DEP_AWS_LIBS} ${PLATFORM_LIBS})

aws_prepare_shared_lib_exports(${PROJECT_NAME})

install(FILES ${AWS_AUTH_ROOT_HEADERS} DESTINATION "include/aws/auth" COMPONENT Development)

if (BUILD_SHARED_LIBS)
   set (TARGET_DIR "shared")
else()
   set (TARGET_DIR "static")
endif()

install(EXPORT "${PROJECT_NAME}-targets"
        DESTINATION "${LIBRARY_DIRECTORY}/${PROJECT_NAME}/cmake/${TARGET_DIR}/"
        NAMESPACE AWS::
        COMPONENT Development)

configure_file("cmake/${PROJECT_NAME}-config.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake"
        @ONLY)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake"
        DESTINATION "${LIBRARY_DIRECTORY}/${PROJECT_NAME}/cmake/"
        COMPONENT Development)

include(CTest)
if (BUILD_TESTING)
    add_subdirectory(tests)
endif()
