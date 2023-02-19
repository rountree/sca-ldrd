sym2: sym2.c
	gcc -Wall -Wextra -Werror -std=c2x -Ofast -o sym2 sym2.c -lcrypto

sym: sym.c
	gcc -Wall -Wextra -Werror -std=c2x -Ofast -o sym sym.c -lcrypto

sizeof: sizeof.c
	gcc -Wall -Wextra -Werror -std=c2x -o sizeof sizeof.c

clean:
	rm -f sym sym2 sizeof

run:
	numactl --physcpubind=70 ./sym2



