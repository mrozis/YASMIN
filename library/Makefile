CC=gcc
CFLAGS=-ldl -shared -fPIC -Wall
INCLUDEFLAGS = -I /usr/src/linux-headers-3.16.0-4-common/include/uapi

TARGET = sock_lib.so
OBJS = socket_library.c


$(TARGET): $(OBJS)
	$(CC) $(INCLUDEFLAGS) $(CFLAGS) -o $(TARGET) $(OBJS)

all : $(TARGET)

clean : 
	rm $(TARGET)
