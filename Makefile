
build: client

client: client.cpp helpers.cpp requests.cpp buffer.cpp
	g++ -std=c++11 -o client client.cpp helpers.cpp requests.cpp buffer.cpp
	
clean:
	rm -rf client *.o
