TARGETS = play mydaemon
ALL: $(TARGETS)

CFLAGS ?= -Wall

play: play.c play.h
	$(CC) $(CFLAGS) -o play play.c
mydaemon: small-talk-daemon-types.c
	$(CC) $(CFLAGS) -lsystemd -o mydaemon small-talk-daemon-types.c

clean:
	rm -f *~
	rm -f $(TARGETS)

