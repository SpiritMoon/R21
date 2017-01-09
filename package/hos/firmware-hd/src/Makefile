target=firmware-hd

ALL: ${target}

objects=firmware-hd.o

${target}: ${objects}
	$(CXX) -o ${target} ${objects}

clean:
	@rm -rf ${objects}
