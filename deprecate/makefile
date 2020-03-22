# ***********************************************
#                    ToraProjects
#                    TBLSIBI
#                    Tight BLS ID based Ident.
#
#                    2019
# ***********************************************

# DIR-STRUCTURE DECLARES
SRCDIR   = src
OBJDIR   = obj
BINDIR   = bin
TESTDIR   = test
SAMPLEDIR = sample
MAINDIR = main
IDIR = include
LIBF = libid2.so
# do not include the final / in the following variables
INSTDIR_INCLUDE = /usr/include/id2
INSTDIR_LIBRARY = /usr/lib

# generate the list of objects to be compiled
SOURCES  := $(wildcard $(SRCDIR)/*.c)
CPPSOURCES := $(wildcard $(SRCDIR)/*.cpp)
OBJECTS  := $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.co)
OBJECTCPPS  := $(CPPSOURCES:$(SRCDIR)/%.cpp=$(OBJDIR)/%.cxx.o)

# generate the list of tests binaries
TESTS := $(wildcard $(TESTDIR)/*.c)
TESTP := $(TESTS:$(TESTDIR)/%.c=$(BINDIR)/%.testbin)
TESTCPPS := $(wildcard $(TESTDIR)/*.cpp)
TESTCPPP := $(TESTCPPS:$(TESTDIR)/%.cpp=$(BINDIR)/%.testbin)

# generate the list of sample binaries
SAMPLES := $(wildcard $(SAMPLEDIR)/*.c)
SAMPLEP := $(SAMPLES:$(SAMPLEDIR)/%.c=$(BINDIR)/%.sample)
SAMPLECPPS := $(wildcard $(SAMPLEDIR)/*.cpp)
SAMPLECPPP := $(SAMPLECPPS:$(SAMPLEDIR)/%.cpp=$(BINDIR)/%.sample)

# generate the list of target
MAINS := $(wildcard $(MAINDIR)/*.c)
MAINP := $(MAINS:$(MAINDIR)/%.c=$(BINDIR)/%.out)
MAINCPPS := $(wildcard $(MAINDIR)/*.cpp)
MAINCPPP := $(MAINCPPS:$(MAINDIR)/%.cpp=$(BINDIR)/%.out)

# flags and compiler defines
CPP = g++
# preventing undefined reference to `std::ios_base::Init::Init()' from happening
# read more :https://stackoverflow.com/questions/10906275/undefined-reference-to-stdios-baseinitinit
#CC = gcc
CC = g++

#CLIBS = -lm -lpthread -lrt -maes -msse4 -lmsgpackc -lcrypto -lgnutlsxx -lgnutls -lssl
CLIBS = -lstdc++ -lgmp -lpbc -lsodium -lcjson -fpermissive
CPPLIBS = -lstdc++ -lgmp -lpbc -lsodium -lcjson

CFLAGS= -O3 -Wall -march=native -I$(IDIR) -I.
CPPFLAGS = -Wall -I$(IDIR) -I.

# standard command defines
rm = rm --f
ls = ls

# default target
.PHONY: all
all:	tests samples mains $(LIBF)
	@echo 'make done'
	@$(ls) $(BINDIR)

# mains - programs that are intended deliverables of the c/c++ project
.PHONY: mains
mains : $(MAINP) $(MAINCPPP)
	@echo 'Mains compiled'

$(LIBF) :
	$(CC) -shared $(OBJECTS) $(OBJECTCPPS) -o $@ $(CLIBS) $(CFLAGS)
	@echo 'Shared object $(LIBF) compiled'

$(MAINP) : $(BINDIR)/%.out: $(MAINDIR)/%.c $(OBJECTS) $(OBJECTCPPS)
	$(CC) $(OBJECTS) $(OBJECTCPPS) -o $@ $(CLIBS) $(CFLAGS)

# edit - using c objects
$(MAINCPPP) : $(BINDIR)/%.out: $(MAINDIR)/%.cpp $(OBJECTS) $(OBJECTCPPS)
	$(CPP) $(OBJECTS) $(OBJECTCPPS) $< -o $@ $(CPPLIBS) $(CPPFLAGS)

# samples - sample program to help implementation (usually for libs)
.PHONY: samples
samples : $(SAMPLEP) $(SAMPLECPPP)
	@echo 'Samples compiled'

# To run sample dir, please do the following first:
# export LD_LIBRARY_PATH=<path to the libid2.so file>
$(SAMPLEP) : $(BINDIR)/%.sample : $(SAMPLEDIR)/%.c $(LIBF)
	gcc -L. $< -o $@ -O3 -Wall -march=native -I$(IDIR) -lid2

$(SAMPLECPPP) : $(BINDIR)/%.sample : $(SAMPLEDIR)/%.cpp $(LIBF)
	g++ -L. $< -o $@ -Wall -I$(IDIR) -lid2

# tests - unit tests made to ensure the functionality and correctness of the library
.PHONY: tests
tests :	$(TESTP) $(TESTCPPP)
	@echo 'Tests Compiled'

$(TESTP) : $(BINDIR)/%.testbin : $(TESTDIR)/%.c $(OBJECTS) $(OBJECTCPPS)
	$(CC) $(OBJECTS) $(OBJECTCPPS) $< -o $@ $(CLIBS) $(CFLAGS)

$(TESTCPPP) : $(BINDIR)/%.testbin : $(TESTDIR)/%.cpp $(OBJECTS) $(OBJECTCPPS)
	$(CPP) $(OBJECTS) $(OBJECTCPPS) $ $< -o $@ $(CPPLIBS) $(CPPFLAGS)

# objects
$(OBJECTS) : $(OBJDIR)/%.co : $(SRCDIR)/%.c
	$(CC) -c $< -o $@ $(CLIBS) $(CFLAGS) -fPIC

$(OBJECTCPPS) : $(OBJDIR)/%.cxx.o : $(SRCDIR)/%.cpp
	$(CPP) -c $< -o $@ $(CPPLIBS) $(CPPFLAGS) -fPIC

# utils - cleanup
.PHONEY: clean
clean:
	@echo "Clearing builds..."
	@$(rm) $(OBJDIR)/*
	@$(rm) $(BINDIR)/*
	@$(rm) $(LIBF)

# debugging
.PHONEY: print
print:
	@echo OBJECTS
	@echo $(OBJECTS)
	@echo $(OBJECTCPPS)
	@echo TEST
	@echo $(TESTP)
	@echo $(TESTCPPP)
	@echo SAMPLE
	@echo $(SAMPLEP)
	@echo $(SAMPLECPPP)
	@echo MAIN
	@echo $(MAINP)
	@echo $(MAINCPPP)

.PHONY: install uninstall
install: $(LIBF)
	@echo 'installing to /usr/lib/ and /usr/include/id2'
	@cp $(LIBF) $(INSTDIR_LIBRARY)/$(LIBF)
	@cp -r $(IDIR) $(INSTDIR_INCLUDE)
	@ls $(INSTDIR_INCLUDE)
	@ls $(INSTDIR_LIBRARY) | grep $(LIBF)
	@echo "Please run ldconfig as superuse!"

uninstall: /usr/lib/$(LIBF)
	@echo 'uninstalling from /usr/lib/ and /usr/include/id2'
	@rm -r $(INSTDIR_INCLUDE)
	@rm $(INSTDIR_LIBRARY)/$(LIBF)


