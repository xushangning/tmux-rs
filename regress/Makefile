TESTS := $(wildcard *.sh)

.PHONY: all $(TESTS)
.NOTPARALLEL: all $(TESTS)

all: $(TESTS)

$(TESTS):
	sh $*.sh
	sleep 1
