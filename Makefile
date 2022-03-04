TARGETS = play my_pam_module.so hello hello-cpp
ALL: $(TARGETS)

CFLAGS ?= -Wall

play: play.c play.h
	$(CC) $(CFLAGS) -o play play.c -lpam -lpam_misc
mydaemon: small-talk-daemon-types.c
	$(CC) $(CFLAGS) -lsystemd -o mydaemon small-talk-daemon-types.c
my_pam_module.so: my_pam_module.c
	$(CC) $(CFLAGS) -fPIC -shared -o my_pam_module.so my_pam_module.c -lpam
hello: hello.c
	$(CC) $(CFLAGS) -o hello hello.c
hello-cpp: hello.cpp
	$(CXX) $(CXXFLAGS) -o hello-cpp hello.cpp

clean:
	rm -f *~
	rm -f $(TARGETS)

