TARGETS = play
ALL: $(TARGETS)

play: play.c play.h
	$(CC) $(CFLAGS) -o play play.c

clean:
	rm -f *~
	rm -f $(TARGETS)

