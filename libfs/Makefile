# Target library
lib := libfs.a

all: $(lib)

$(lib): fs.o disk.o
	ar rcs $(lib) fs.o disk.o
fs.o: fs.c fs.h disk.h
	gcc -g -Wall -Wextra -c -o fs.o fs.c
disk.o: disk.c disk.h
	gcc -g -Wall -Wextra -c -o disk.o disk.c

clean: 
	rm -rf $(lib) fs.o disk.o
## TODO: Phase 1
