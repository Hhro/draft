test: 
	gcc -S test.c -o train.s -masm=intel -fno-asynchronous-unwind-tables
	cp train.s estimate.s
	python3 training-estimating.py ./train.s ./estimate.s