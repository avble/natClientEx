#!/bin/sh 
#./iceController -s 116.100.19.166:3478  -U device5
#./natController -s stun.l.google.com:19302  -U device5
./natController -s 52.88.150.119:3478 -U device5 -t 52.88.150.119:3478 -u 100  -p 100 -T
#./natController -R -s 203.205.30.23:3478 -U device1 -t 203.205.30.23:3478 -u 100  -p 100 -T
	


