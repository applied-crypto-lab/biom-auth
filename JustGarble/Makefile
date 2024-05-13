# ***********************************************
#                    JustGarble
# ***********************************************

SRCDIR   = src
OBJDIR   = obj
BINDIR   = bin
TESTDIR   = test
CIRCUITDIR = circuit_files
OBJECTFULL = obj/*.o

SOURCES  := $(wildcard $(SRCDIR)/*.c)
INCLUDES := $(wildcard $(SRCDIR)/*.h)
OBJECTS  := $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

IDIR =../include
CC = gcc
CFLAGS= -lm -lrt -lpthread -maes -msse4 -lmsgpack-c -march=native -I$(IDIR)

LOCAL = circuit_test_and_gen
rm = rm --f


targets: LOCAL

debug: CFLAGS += -O0 -DDEBUG -g
debug: targets

opt: CFLAGS += -O2
opt: targets


LOCAL: $(OBJECTS) $(TESTDIR)/$(LOCAL).c
	$(CC) $(OBJECTFULL) $(TESTDIR)/$(LOCAL).c -o $(BINDIR)/$(LOCAL) $(LIBS) $(CFLAGS)

$(OBJECTS): $(OBJDIR)/%.o : $(SRCDIR)/%.c
	$(CC) -c $< -o $@ $(LIBS) $(CFLAGS)


.PHONEY: clean
clean:
	@$(rm) $(OBJECTS)
	@$(rm) $(BINDIR)/$(LOCAL)

.PHONEY: cleanscd
cleanscd:
	@$(rm) $(CIRCUITDIR)/*.scd

.PHONEY: cleanall
cleanall:
	@$(rm) $(OBJECTS)
	@$(rm) $(BINDIR)/$(LOCAL)
	@$(rm) $(CIRCUITDIR)/*.scd
