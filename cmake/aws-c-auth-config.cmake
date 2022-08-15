include(CMakeFindDependencyMacro)
include(AwsCrtLoadTarget)

find_dependency(aws-c-common)
find_dependency(aws-c-cal)
find_dependency(aws-c-io)
find_dependency(aws-c-http)
find_dependency(aws-c-sdkutils)

aws_load_target_default(@PROJECT_NAME@)
