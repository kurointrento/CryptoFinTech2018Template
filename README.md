# Acknowledgement
This template is derived from the work done by Elia Geretto (elia.geretto@studenti.unitn.it), in the Research Project Course (Fall 2017), advised by Prof. Fabio Massacci (fabio.massacci@unitn.it) and TA Chan Nam Ngo (channam.ngo@unitn.it).

# Build instructions

### Cloning
First of all, in order to build this project, it should be cloned with all the
necessary submodules. This can be done as follows:

	$ git clone --recursive <project-url>

Or, if you already cloned the project, you can enter the project directory and
then use:

	$ git submodule init
	$ git submodule update

### CMake
The building of the project happens out-of-tree, so it is necessary to create a
separate directory that holds all the building related files:

	$ mkdir build

After this, it is necessary to initialize the build system using CMake:
	
	$ cd build
	$ cmake ..

### Building
After setting up the environment, the project can be build using Make:

	$ make -j<number-of-cores>

The project is compiled using OpenMP and is set to use the dynamically generated
bn128 implementation. This last option may give some problems on certain
configurations since it requires the heap for the process to be executable. On
Fedora, or other distributions using SELinux, this can be allowed using:

	# setsebool allow_execheap on

A complete list of the dependencies to be installed is provided on the GitHub
page for `libsnark`.

### Clang++
The project can also be build with the Clang++ compiler; it can be done
modifying the `cmake` command in the following way:

	$ cmake -DCMAKE_CXX_STANDARD=11 CXX=clang++ ..
