CXX=g++
OPTS=-O
CFLAGS=$(OPTS) -Wall
SRC=../src

WOFPROB_SRC=$(SRC)/main.cpp $(SRC)/parser.cpp $(SRC)/parser_util.cpp $(SRC)/string_util.cpp

all: wofprob

wofprob: $(WOFPROB_SRC)
	$(CXX) $(CFLAGS) $^ -o $@

clean:
	- rm -f wofprob wofprob.exe
