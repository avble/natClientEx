APP=iceController
APP_CLIENT=nat_lient
APP2 = xml2test

CC=gcc

#include 
CFLAGS += -I../pjlib/include/ -I../pjlib-util/include  -I../pjnath/include
CFLAGS += -I./include
#debug
CFLAGS += -g

#Link flag 
LDFLAGS = -L../pjlib-util/lib 
LDFLAGS += -L../pjnath/lib 
LDFLAGS += -L../pjmedia/lib 
LDFLAGS += -L../pjsip/lib 
LDFLAGS += -L../third_party/lib            
LDFLAGS += -L../pjlib/lib
LDFLAGS += -L./  -lcurl  -lxml2
LDFLAGS += -lpjsua-x86_64-unknown-linux-gnu -lpjsip-ua-x86_64-unknown-linux-gnu -lpjsip-simple-x86_64-unknown-linux-gnu -lpjsip-x86_64-unknown-linux-gnu -lpjmedia-codec-x86_64-unknown-linux-gnu -lpjmedia-x86_64-unknown-linux-gnu -lpjmedia-videodev-x86_64-unknown-linux-gnu -lpjmedia-audiodev-x86_64-unknown-linux-gnu -lpjmedia-x86_64-unknown-linux-gnu -lpjnath-x86_64-unknown-linux-gnu -lpjlib-util-x86_64-unknown-linux-gnu  -lsrtp-x86_64-unknown-linux-gnu -lresample-x86_64-unknown-linux-gnu -lgsmcodec-x86_64-unknown-linux-gnu -lspeex-x86_64-unknown-linux-gnu -lilbccodec-x86_64-unknown-linux-gnu -lg7221codec-x86_64-unknown-linux-gnu -lportaudio-x86_64-unknown-linux-gnu  -lpj-x86_64-unknown-linux-gnu  -luuid  -lm -lrt -lpthread 
#LDFLAGS += -lpjsua-x86_64-unknown-linux-gnu -lpjsip-ua-x86_64-unknown-linux-gnu -lpjsip-simple-x86_64-unknown-linux-gnu -lpjsip-x86_64-unknown-linux-gnu -lpjmedia-codec-x86_64-unknown-linux-gnu -lpjmedia-x86_64-unknown-linux-gnu -lpjmedia-videodev-x86_64-unknown-linux-gnu -lpjmedia-audiodev-x86_64-unknown-linux-gnu -lpjmedia-x86_64-unknown-linux-gnu -lpjnath-x86_64-unknown-linux-gnu -lpjlib-util-x86_64-unknown-linux-gnu  -lsrtp-x86_64-unknown-linux-gnu -lresample-x86_64-unknown-linux-gnu -lgsmcodec-x86_64-unknown-linux-gnu -lspeex-x86_64-unknown-linux-gnu -lilbccodec-x86_64-unknown-linux-gnu -lg7221codec-x86_64-unknown-linux-gnu -lportaudio-x86_64-unknown-linux-gnu  -lpj-x86_64-unknown-linux-gnu -lssl -lcrypto -ldl -lz -luuid -lm -lrt -lpthread  

#dynamic link 
LDFLAGS += -Wl,-rpath=./ 



SRCS =   icewrapper.c 
SRCS +=   utilities.c 
SRCS +=  httpwrapper.c 
SRCS +=  icecontroller.c 
SRCS +=  getline.c 
SRCS +=  xml2wrapper.c 



OBJS = $(patsubst %.c,%.o,$(SRCS))

all:  $(OBJS)
	$(CC) -o $(APP)  $(OBJS) $(LDFLAGS)  
	
CLIENT_SRCS =   icewrapper.c 
CLIENT_SRCS +=   iceclient.c 
CLIENT_SRCS +=  httpwrapper.c 
CLIENT_SRCS +=  getline.c 
CLIENT_SRCS +=  xml2wrapper.c 

OBJS_CLIENT = $(patsubst %.c,%.o,$(CLIENT_SRCS))

client: $(OBJS_CLIENT)
	gcc -o $(APP_CLIENT) $(OBJS_CLIENT)  $(LDFLAGS)  


%.o: %.c
	$(CC) -c $(CFLAGS)  $< -o $@


clean:
	rm -f $(APP) *.o
