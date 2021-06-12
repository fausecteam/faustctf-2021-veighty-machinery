CC = gcc
CFLAGS = -Wextra -Werror=extra -fexceptions -Wall
DEBUG_FLAGS = -DDEBUG -g

CDIR = src
INCDIR = src/include
OUTDIR = build/release
DEBUG_OUTDIR = build/debug

SOURCES = $(wildcard $(CDIR)/*.c)

OBJS = $(SOURCES:$(CDIR)/%.c=$(OUTDIR)/%.o)
DEBUG_OBJS = $(SOURCES:$(CDIR)/%.c=$(DEBUG_OUTDIR)/%.o)
HEADERS = $(wildcard $(INCDIR)/*.h)

TARGET = veighty-machinery
DEBUG_TARGET = $(TARGET)-debug

.PHONY: all debug

all: $(TARGET)
debug: $(DEBUG_TARGET)

$(OUTDIR) $(DEBUG_OUTDIR):
	mkdir -p $@

$(OUTDIR)/%.o: $(CDIR)/%.c $(HEADERS) | $(OUTDIR)
	$(CC) $(CFLAGS) -I $(INCDIR) -c -o $@ $<

$(DEBUG_OUTDIR)/%.o: $(CDIR)/%.c $(HEADERS) | $(DEBUG_OUTDIR)
	$(CC) $(CFLAGS) $(DEBUG_FLAGS) -I $(INCDIR) -c -o $@ $<

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^
	strip $@

$(DEBUG_TARGET): $(DEBUG_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

.PHONY:
clean:
	rm -rf $(OBJS) $(OUTDIR) $(DEBUG_OUTDIR)

.PHONY:
dist-clean: clean
	rm -f $(TARGET) $(DEBUG_TARGET)
