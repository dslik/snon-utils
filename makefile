CC=gcc
CFLAGS=-I.
DEPS = cJSON.h sha1.h snon_utils.h test_utils.cc snon_tests.cc
OBJ = cJSON.o sha1.o snon_utils.o test_utils.o snon_tests.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

tests: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

