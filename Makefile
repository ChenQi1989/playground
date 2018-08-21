TARGETS = play
ALL: $(TARGETS)

CFLAGS ?= -Wall

play: play.c play.h
	$(CC) $(CFLAGS) -o play play.c

clean:
	rm -f *~
	rm -f $(TARGETS)

