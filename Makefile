syn_cap:
	gcc -Wall -g -o syn_cap ./*.c -lpthread
clean:
	rm -rf ./syn_cap
