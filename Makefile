#name: Hao Bai
#University ID: 21242020

main: 
	gcc sniffer.c -o sniffer -lpcap
	gcc rst-http.c -o rst-http -lpcap -lnet
	gcc hijack-telnet.c -o hijack-telnet -lpcap -lnet

clean:
	-rm -f *.o *~ sniffer rst-http hijack-telnet