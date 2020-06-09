## AWS C Auth

C99 library implementation of AWS client-side authentication: standard credentials providers and signing.


## License

This library is licensed under the Apache 2.0 License. 

## Usage

### Building

Note that aws-c-auth has several dependencies.  If you are building on Linux, you will need to follow the build instructions for [s2n](https://github.com/awslabs/s2n/blob/master/docs/USAGE-GUIDE.md) in order to build the aws-c-io dependency.

````
git clone git@github.com:awslabs/aws-c-common.git
cmake -DCMAKE_PREFIX_PATH=<install-path> -DCMAKE_INSTALL_PREFIX=<install-path> -S aws-c-common -B aws-c-common/build
cmake --build aws-c-common/build --target install

git clone git@github.com:awslabs/aws-c-io.git
cmake -DCMAKE_PREFIX_PATH=<install-path> -DCMAKE_INSTALL_PREFIX=<install-path> -S aws-c-io -B aws-c-io/build
cmake --build aws-c-io/build --target install

git clone git@github.com:awslabs/aws-c-compression.git
cmake -DCMAKE_PREFIX_PATH=<install-path> -DCMAKE_INSTALL_PREFIX=<install-path> -S aws-c-compression -B aws-c-compression/build
cmake --build aws-c-compression/build --target install

git clone git@github.com:awslabs/aws-c-http.git
cmake -DCMAKE_PREFIX_PATH=<install-path> -DCMAKE_INSTALL_PREFIX=<install-path> -S aws-c-http -B aws-c-http/build
cmake --build aws-c-http/build --target install

git clone git@github.com:awslabs/aws-c-cal.git
cmake -DCMAKE_PREFIX_PATH=<install-path> -DCMAKE_INSTALL_PREFIX=<install-path> -S aws-c-cal -B aws-c-cal/build
cmake --build aws-c-cal/build --target install

git clone git@github.com:awslabs/aws-c-auth.git
cmake -DCMAKE_PREFIX_PATH=<install-path> -DCMAKE_INSTALL_PREFIX=<install-path> -S aws-c-auth -B aws-c-auth/build
cmake --build aws-c-auth/build --target install
````
