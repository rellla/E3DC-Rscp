CXX=g++
ROOT_VALUE=Rscp

all: $(ROOT_VALUE)

$(ROOT_VALUE): clean
	$(CXX) -O3 RscpMain.cpp RscpProtocol.cpp AES.cpp SocketConnection.cpp -o $@


clean:
	-rm $(ROOT_VALUE) $(VECTOR)
