APP=iceController
APP_CLIENT=iceclient
APP2 = xml2test

CC=arm-openwrt-linux-gcc

CFLAGS += -L../pjlib/lib 
CFLAGS += -L../pjlib-util/lib 
CFLAGS += -L../pjnath/lib 
CFLAGS += -L../pjmedia/lib 
CFLAGS += -L../pjsip/lib 
CFLAGS += -L../third_party/lib            

#CFLAGS += -lpjsua-x86_64-unknown-linux-gnu -lpjsip-ua-x86_64-unknown-linux-gnu -lpjsip-simple-x86_64-unknown-linux-gnu -lpjsip-x86_64-unknown-linux-gnu -lpjmedia-codec-x86_64-unknown-linux-gnu -lpjmedia-x86_64-unknown-linux-gnu -lpjmedia-videodev-x86_64-unknown-linux-gnu -lpjmedia-audiodev-x86_64-unknown-linux-gnu -lpjmedia-x86_64-unknown-linux-gnu -lpjnath-x86_64-unknown-linux-gnu -lpjlib-util-x86_64-unknown-linux-gnu  -lsrtp-x86_64-unknown-linux-gnu -lresample-x86_64-unknown-linux-gnu -lgsmcodec-x86_64-unknown-linux-gnu -lspeex-x86_64-unknown-linux-gnu -lilbccodec-x86_64-unknown-linux-gnu -lg7221codec-x86_64-unknown-linux-gnu -lportaudio-x86_64-unknown-linux-gnu  -lpj-x86_64-unknown-linux-gnu -lssl -lcrypto -ldl -lz -luuid -lm -lrt -lpthread  -lasound

CFLAGS += -lpjsua-arm-unknown-linux-gnu -lpjsip-ua-arm-unknown-linux-gnu -lpjsip-simple-arm-unknown-linux-gnu -lpjsip-arm-unknown-linux-gnu -lpjmedia-codec-arm-unknown-linux-gnu -lpjmedia-arm-unknown-linux-gnu -lpjmedia-videodev-arm-unknown-linux-gnu -lpjmedia-audiodev-arm-unknown-linux-gnu -lpjmedia-arm-unknown-linux-gnu -lpjnath-arm-unknown-linux-gnu -lpjlib-util-arm-unknown-linux-gnu  -lsrtp-arm-unknown-linux-gnu -lresample-arm-unknown-linux-gnu -lgsmcodec-arm-unknown-linux-gnu -lspeex-arm-unknown-linux-gnu -lilbccodec-arm-unknown-linux-gnu -lg7221codec-arm-unknown-linux-gnu   -lpj-arm-unknown-linux-gnu -ldl  -lm -lrt -lpthread  

#CFLAGS += -lpjsua-arm-unknown-linux-gnu -lpjsip-ua-arm-unknown-linux-gnu -lpjsip-simple-arm-unknown-linux-gnu -lpjsip-arm-unknown-linux-gnu -lpjmedia-codec-arm-unknown-linux-gnu -lpjmedia-arm-unknown-linux-gnu -lpjmedia-videodev-arm-unknown-linux-gnu -lpjmedia-audiodev-arm-unknown-linux-gnu -lpjmedia-arm-unknown-linux-gnu -lpjnath-arm-unknown-linux-gnu -lpjlib-util-arm-unknown-linux-gnu  -lsrtp-arm-unknown-linux-gnu -lresample-arm-unknown-linux-gnu -lgsmcodec-arm-unknown-linux-gnu -lspeex-arm-unknown-linux-gnu -lilbccodec-arm-unknown-linux-gnu -lg7221codec-arm-unknown-linux-gnu   -lpj-arm-unknown-linux-gnu -ldl -lz -luuid -lm -lrt -lpthread  

#include 
CFLAGS += -I../pjlib/include/ -I../pjlib-util/include  -I../pjnath/include
CFLAGS += -I./include

#dynamic link 
CFLAGS += -L./ -lcurl 
CFLAGS += -L./ -lxml2 
CFLAGS += -Wl,-rpath=./ 

CFLAGS += -DPJ_IS_BIG_ENDIAN=0 -DPJ_IS_LITTLE_ENDIAN=1


#debug
CFLAGS += -g

SRCS =   icewrapper.c 
SRCS +=  httpwrapper.c 
SRCS +=  icecontroller.c 
SRCS +=  getline.c 
SRCS +=  xml2wrapper.c 


all: 
	$(CC) -o $(APP) $(SRCS)  $(CFLAGS)  
#	$(CC) -o $(APP2) -DBUILD_XMLWRAPPER xml2wrapper.c $(CFLAGS)  
	


clean:
	rm -f $(APP)
