all: 1m-block

1m-block: 1m-block.cpp
	g++ -o 1m-block 1m-block.cpp -lnetfilter_queue -lnet

clean:
	rm -f 1m-block
