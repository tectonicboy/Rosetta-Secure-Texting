.PHONY: bench debug

bench:
	cat /dev/null > ../compiler-report.txt && \
	cc bench.c -O3 -march=native -Wall -Wextra -o bench \
	-fopt-info-loop-optimized=../compiler-report.txt \
	#-ffast-math

debug:
	cc bench.c -O3 -g -march=native -Wall -Wextra -o bench-debug
