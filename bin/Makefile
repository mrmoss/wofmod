CXX=g++
OPTS=-O
CFLAGS=$(OPTS) -Wall
SRC=../src

WOFPROBE_SRC=$(SRC)/main.cpp $(SRC)/probe.cpp $(SRC)/parser_util.cpp $(SRC)/string_util.cpp

all: wofprobe

wofprobe: $(WOFPROBE_SRC)
	$(CXX) $(CFLAGS) $^ -o $@

clean:
	- rm -f wofprobe wofprobe.exe
