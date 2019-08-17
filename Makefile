CC=g++
CFLAGS=-std=c++14 -g
OBJ=main.o address.o arp_header.o arp_packet.o ethernet_header.o arp_spoofing.o etc_function.o hardware.o protocol.o
Target=arp_spoof

all : ${Target}

${Target}: ${OBJ}
	${CC} ${CFLAGS} -o ${Target} ${OBJ} -lpcap -lpthread

main.o:
	${CC} ${CFLAGS} -c -o main.o main.cpp -lpthread

address.o:
	${CC} ${CFLAGS} -c -o address.o address.cpp

arp_header.o:
	${CC} ${CFLAGS} -c -o arp_header.o arp_header.cpp

arp_packet.o:
	${CC} ${CFLAGS} -c -o arp_packet.o arp_packet.cpp

arp_spoofing.o:
	${CC} ${CFLAGS} -c -o arp_spoofing.o arp_spoofing.cpp -lpcap

ethernet_header.o:
	${CC} ${CFLAGS} -c -o ethernet_header.o ethernet_header.cpp

etc_function.o:
	${CC} ${CFLAGS} -c -o etc_function.o etc_function.cpp -fno-stack-protector

hardware.o:
	${CC} ${CFLAGS} -c -o hardware.o hardware.cpp

protocol.o:
	${CC} ${CFLAGS} -c -o protocol.o protocol.cpp

clean:
	rm -f ${Target}
	rm -f ${OBJ}

