#!/bin/sh 

# build lixml2
cd libxml2-2.9.2 && ./myconfig.sh && make  && cd ..
cp libxml2-2.9.2/.libs/libxml2.a ./pjproject-2.4/example

#build libcur 
cd curl-7.42.1 && ./myconfig.sh && make  && cd ..
cp curl-7.42.1/lib/.libs/libcurl.a ./pjproject-2.4/example

# build pjnath 
cd pjproject-2.4 && ./myconfig.sh && make dep && make clean && make lib && cd ..

# build app 

cd pjproject-2.4/example  && make  && cd ../../

