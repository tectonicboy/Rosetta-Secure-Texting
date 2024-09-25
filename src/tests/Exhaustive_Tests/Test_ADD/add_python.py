import sys

a = int(sys.argv[1], 2)
b = int(sys.argv[2], 2)
f = open("python_add_result.txt", "w")
f.write(bin(a+b))
print("Wrote the ADD result to file:")
print(bin(a+b))
f.close()

