.PHONY: xml2 curl pjproject
.PHONY: cfg_xml2 cfg_curl cfg_pjproject

all: xml2 curl pjproject app
	echo "finish building "

app: 
	cd pjproject-2.4/example  && make  && cd ../../

xml2:
	cd libxml2-2.9.2 && make  && cd .. 
	cp -rf libxml2-2.9.2/.libs/libxml2.a ./pjproject-2.4/example
	cp -rf libxml2-2.9.2/include/libxml ./pjproject-2.4/example/include/ 

curl:
	cd curl-7.42.1 && make  && cd .. 
	cp curl-7.42.1/lib/.libs/libcurl.a ./pjproject-2.4/example
	cp -rf curl-7.42.1/include/curl ./pjproject-2.4/example/include/ 

pjproject:
	cd pjproject-2.4 && make  dep && make && cd .. 

config: cfg_xml2 cfg_curl cfg_pjproject
	echo "Finish configuration" 	

cfg_xml2:
	cd libxml2-2.9.2 && ./configure && cd ..
	#cd libxml2-2.9.2 && ./myconfig.sh && cd ..

cfg_curl:
	cd curl-7.42.1 && ./myconfig.sh && make  && cd ..

cfg_pjproject:
	cd pjproject-2.4 && ./myconfig.sh && make dep && make clean && make lib && cd ..


clean:
	cd pjproject-2.4/example  && make  clean && cd ../../
	cd libxml2-2.9.2 && make  clean && cd .. 
	cd curl-7.42.1 && make clean  && cd .. 
	cd pjproject-2.4 && make  clean && cd .. 
