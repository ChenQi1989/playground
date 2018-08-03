TARGETS = test
ALL: $(TARGETS)

test: test.c test.h
	$(CC) -o test test.c

clean:
	rm -f *~
	rm -f $(TARGETS)

