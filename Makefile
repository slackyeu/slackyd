NAME    = slackyd

CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -ansi -pedantic
LIBS    = -lbz2 -lssl
SRC     = src
OBJ     = $(SRC)/main.o $(SRC)/func.o $(SRC)/net.o $(SRC)/search.o $(SRC)/update.o $(SRC)/md5.o $(SRC)/packages.o

ifeq (, $(DESTDIR))
 BINDIR  = /usr/bin/
 CONFDIR = /etc/$(NAME)
 VARDIR  = /var/$(NAME)
else
 BINDIR  = $(DESTDIR)/usr/bin/
 CONFDIR = $(DESTDIR)/etc/$(NAME)
 VARDIR  = $(DESTDIR)/var/$(NAME)
endif

debug   = yes
mtrace  = no
profile = no

ifeq ($(debug), yes)
 CFLAGS += -g3 -ggdb3 -DDEBUG
 endif
ifeq ($(mtrace), yes)
 CFLAGS += -DMTRACE
endif
ifeq ($(profile), yes)
 CFLAGS += -pg -DPROFILE
endif

all:	 $(OBJ)
	 $(CC) $(CFLAGS) -o $(NAME) $(OBJ) $(LIBS)
	 @echo
	 @echo "Now run make install."
	 @echo

main.o:      $(SRC)/main.c
	     $(SRC)/main.o
func.o:      $(SRC)/func.c
	     $(SRC)/func.o
net.o:       $(SRC)/net.c
	     $(SRC)/net.o
search.o:    $(SRC)/search.c 
	     $(SRC)/search.o
update.o:    $(SRC)/update.c
	     $(SRC)/update.o
md5.o:       $(SRC)/md5.c
	     $(SRC)/md5.o
packages.o : $(SRC)/packages.c
	     $(SRC)/packages.o

clean: 
	rm -f $(OBJ) $(NAME)
	@echo
	@echo "Object and binary files succesfull delete."
	@echo

install: $(NAME)
	mkdir -m 755 -p $(BINDIR)
	mkdir -m 755 -p $(CONFDIR)
	mkdir -m 777 -p $(VARDIR)
	install -m 755 slackyd $(BINDIR)
	install -b -m 644 slackyd.conf $(CONFDIR)
	@echo
	@echo "Slackyd succesfull installed."
	@echo
uninstall: 
	rm -fr  $(BINDIR)/slackyd $(CONFDIR) $(VARDIR)
	@echo
	@echo "$(NAME) succesfull uninstalled."
	@echo
