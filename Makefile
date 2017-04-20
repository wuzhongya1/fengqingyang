SRC=httpput.c
OBJ=httpput
CFLAGS=-I/home/lxj/include -I./inc -g 
LDFLAGS=-L/home/lxj/lib -lcurl -lcrypto -lssl -lbase64

$(OBJ):$(SRC)
	gcc -Wall $^ -o $@ $(CFLAGS) $(LDFLAGS)

.PHONY: clean
clean:
	rm $(OBJ)
