project(stscli C)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_INSTALL_PREFIX}/lib/cmake")

file(GLOB STSCLI_SRC
        "*.c"
        )

set(STSCLI_PROJECT_NAME stscli)
add_executable(${STSCLI_PROJECT_NAME} ${STSCLI_SRC})
aws_set_common_properties(${STSCLI_PROJECT_NAME})


target_include_directories(${STSCLI_PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>)

target_link_libraries(${STSCLI_PROJECT_NAME} aws-c-auth)

if (BUILD_SHARED_LIBS AND NOT WIN32)
    message(INFO " stscli will be built with shared libs, but you may need to set LD_LIBRARY_PATH=${CMAKE_INSTALL_PREFIX}/lib to run the application")
endif()

install(TARGETS ${STSCLI_PROJECT_NAME}
        EXPORT ${STSCLI_PROJECT_NAME}-targets
        COMPONENT Runtime
        RUNTIME
        DESTINATION bin
        COMPONENT Runtime)
