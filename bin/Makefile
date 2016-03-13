CXX=g++
OPTS=-O
CFLAGS=$(OPTS) -Wall
SRC=../src

WOFMOD_SRC=$(SRC)/main.cpp $(SRC)/parser.cpp $(SRC)/parser_util.cpp $(SRC)/string_util.cpp

all: wofmod

wofmod: $(WOFMOD_SRC)
	$(CXX) $(CFLAGS) $^ -o $@

clean:
	- rm -f wofmod wofmod.exe