all : arp_sender

arp_sender: main.o address.o arp_header.o arp_packet.o ethernet_header.o arp_spoofing.o etc_function.o hardware.o protocol.o
	g++ -std=c++14 -g -o arp_sender *.o -lpcap -lpthread

main.o:
	g++ -std=c++14 -g -c -o main.o main.cpp -lpthread

address.o:
	g++ -std=c++14 -g -c -o address.o address.cpp

arp_header.o:
	g++ -std=c++14 -g -c -o arp_header.o arp_header.cpp

arp_packet.o:
	g++ -std=c++14 -g -c -o arp_packet.o arp_packet.cpp

arp_spoofing.o:
	g++ -std=c++14 -g -c -o arp_spoofing.o arp_spoofing.cpp -lpcap

ethernet_header.o:
	g++ -std=c++14 -g -c -o ethernet_header.o ethernet_header.cpp

etc_function.o:
	g++ -std=c++14 -g -c -o etc_function.o etc_function.cpp

hardware.o:
	g++ -std=c++14 -g -c -o hardware.o hardware.cpp

protocol.o:
	g++ -std=c++14 -g -c -o protocol.o protocol.cpp

clean:
	rm -f arp_sender
	rm -f *.o

