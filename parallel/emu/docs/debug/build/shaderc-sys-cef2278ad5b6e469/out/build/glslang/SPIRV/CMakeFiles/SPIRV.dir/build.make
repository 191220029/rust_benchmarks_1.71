# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.10

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/caleb/.cargo/registry/src/github.com-1ecc6299db9ec823/shaderc-sys-0.6.2/build

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build

# Include any dependencies generated for this target.
include glslang/SPIRV/CMakeFiles/SPIRV.dir/depend.make

# Include the progress variables for this target.
include glslang/SPIRV/CMakeFiles/SPIRV.dir/progress.make

# Include the compile flags for this target's objects.
include glslang/SPIRV/CMakeFiles/SPIRV.dir/flags.make

glslang/SPIRV/CMakeFiles/SPIRV.dir/GlslangToSpv.cpp.o: glslang/SPIRV/CMakeFiles/SPIRV.dir/flags.make
glslang/SPIRV/CMakeFiles/SPIRV.dir/GlslangToSpv.cpp.o: /home/caleb/.cargo/registry/src/github.com-1ecc6299db9ec823/shaderc-sys-0.6.2/build/glslang/SPIRV/GlslangToSpv.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object glslang/SPIRV/CMakeFiles/SPIRV.dir/GlslangToSpv.cpp.o"
	cd /home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/glslang/SPIRV && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/SPIRV.dir/GlslangToSpv.cpp.o -c /home/caleb/.cargo/registry/src/github.com-1ecc6299db9ec823/shaderc-sys-0.6.2/build/glslang/SPIRV/GlslangToSpv.cpp

glslang/SPIRV/CMakeFiles/SPIRV.dir/GlslangToSpv.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/SPIRV.dir/GlslangToSpv.cpp.i"
	cd /home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/glslang/SPIRV && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/caleb/.cargo/registry/src/github.com-1ecc6299db9ec823/shaderc-sys-0.6.2/build/glslang/SPIRV/GlslangToSpv.cpp > CMakeFiles/SPIRV.dir/GlslangToSpv.cpp.i

glslang/SPIRV/CMakeFiles/SPIRV.dir/GlslangToSpv.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/SPIRV.dir/GlslangToSpv.cpp.s"
	cd /home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/glslang/SPIRV && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/caleb/.cargo/registry/src/github.com-1ecc6299db9ec823/shaderc-sys-0.6.2/build/glslang/SPIRV/GlslangToSpv.cpp -o CMakeFiles/SPIRV.dir/GlslangToSpv.cpp.s

glslang/SPIRV/CMakeFiles/SPIRV.dir/GlslangToSpv.cpp.o.requires:

.PHONY : glslang/SPIRV/CMakeFiles/SPIRV.dir/GlslangToSpv.cpp.o.requires

glslang/SPIRV/CMakeFiles/SPIRV.dir/GlslangToSpv.cpp.o.provides: glslang/SPIRV/CMakeFiles/SPIRV.dir/GlslangToSpv.cpp.o.requires
	$(MAKE) -f glslang/SPIRV/CMakeFiles/SPIRV.dir/build.make glslang/SPIRV/CMakeFiles/SPIRV.dir/GlslangToSpv.cpp.o.provides.build
.PHONY : glslang/SPIRV/CMakeFiles/SPIRV.dir/GlslangToSpv.cpp.o.provides

glslang/SPIRV/CMakeFiles/SPIRV.dir/GlslangToSpv.cpp.o.provides.build: glslang/SPIRV/CMakeFiles/SPIRV.dir/GlslangToSpv.cpp.o


glslang/SPIRV/CMakeFiles/SPIRV.dir/InReadableOrder.cpp.o: glslang/SPIRV/CMakeFiles/SPIRV.dir/flags.make
glslang/SPIRV/CMakeFiles/SPIRV.dir/InReadableOrder.cpp.o: /home/caleb/.cargo/registry/src/github.com-1ecc6299db9ec823/shaderc-sys-0.6.2/build/glslang/SPIRV/InReadableOrder.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object glslang/SPIRV/CMakeFiles/SPIRV.dir/InReadableOrder.cpp.o"
	cd /home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/glslang/SPIRV && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/SPIRV.dir/InReadableOrder.cpp.o -c /home/caleb/.cargo/registry/src/github.com-1ecc6299db9ec823/shaderc-sys-0.6.2/build/glslang/SPIRV/InReadableOrder.cpp

glslang/SPIRV/CMakeFiles/SPIRV.dir/InReadableOrder.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/SPIRV.dir/InReadableOrder.cpp.i"
	cd /home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/glslang/SPIRV && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/caleb/.cargo/registry/src/github.com-1ecc6299db9ec823/shaderc-sys-0.6.2/build/glslang/SPIRV/InReadableOrder.cpp > CMakeFiles/SPIRV.dir/InReadableOrder.cpp.i

glslang/SPIRV/CMakeFiles/SPIRV.dir/InReadableOrder.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/SPIRV.dir/InReadableOrder.cpp.s"
	cd /home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/glslang/SPIRV && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/caleb/.cargo/registry/src/github.com-1ecc6299db9ec823/shaderc-sys-0.6.2/build/glslang/SPIRV/InReadableOrder.cpp -o CMakeFiles/SPIRV.dir/InReadableOrder.cpp.s

glslang/SPIRV/CMakeFiles/SPIRV.dir/InReadableOrder.cpp.o.requires:

.PHONY : glslang/SPIRV/CMakeFiles/SPIRV.dir/InReadableOrder.cpp.o.requires

glslang/SPIRV/CMakeFiles/SPIRV.dir/InReadableOrder.cpp.o.provides: glslang/SPIRV/CMakeFiles/SPIRV.dir/InReadableOrder.cpp.o.requires
	$(MAKE) -f glslang/SPIRV/CMakeFiles/SPIRV.dir/build.make glslang/SPIRV/CMakeFiles/SPIRV.dir/InReadableOrder.cpp.o.provides.build
.PHONY : glslang/SPIRV/CMakeFiles/SPIRV.dir/InReadableOrder.cpp.o.provides

glslang/SPIRV/CMakeFiles/SPIRV.dir/InReadableOrder.cpp.o.provides.build: glslang/SPIRV/CMakeFiles/SPIRV.dir/InReadableOrder.cpp.o


glslang/SPIRV/CMakeFiles/SPIRV.dir/Logger.cpp.o: glslang/SPIRV/CMakeFiles/SPIRV.dir/flags.make
glslang/SPIRV/CMakeFiles/SPIRV.dir/Logger.cpp.o: /home/caleb/.cargo/registry/src/github.com-1ecc6299db9ec823/shaderc-sys-0.6.2/build/glslang/SPIRV/Logger.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object glslang/SPIRV/CMakeFiles/SPIRV.dir/Logger.cpp.o"
	cd /home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/glslang/SPIRV && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/SPIRV.dir/Logger.cpp.o -c /home/caleb/.cargo/registry/src/github.com-1ecc6299db9ec823/shaderc-sys-0.6.2/build/glslang/SPIRV/Logger.cpp

glslang/SPIRV/CMakeFiles/SPIRV.dir/Logger.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/SPIRV.dir/Logger.cpp.i"
	cd /home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/glslang/SPIRV && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/caleb/.cargo/registry/src/github.com-1ecc6299db9ec823/shaderc-sys-0.6.2/build/glslang/SPIRV/Logger.cpp > CMakeFiles/SPIRV.dir/Logger.cpp.i

glslang/SPIRV/CMakeFiles/SPIRV.dir/Logger.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/SPIRV.dir/Logger.cpp.s"
	cd /home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/glslang/SPIRV && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/caleb/.cargo/registry/src/github.com-1ecc6299db9ec823/shaderc-sys-0.6.2/build/glslang/SPIRV/Logger.cpp -o CMakeFiles/SPIRV.dir/Logger.cpp.s

glslang/SPIRV/CMakeFiles/SPIRV.dir/Logger.cpp.o.requires:

.PHONY : glslang/SPIRV/CMakeFiles/SPIRV.dir/Logger.cpp.o.requires

glslang/SPIRV/CMakeFiles/SPIRV.dir/Logger.cpp.o.provides: glslang/SPIRV/CMakeFiles/SPIRV.dir/Logger.cpp.o.requires
	$(MAKE) -f glslang/SPIRV/CMakeFiles/SPIRV.dir/build.make glslang/SPIRV/CMakeFiles/SPIRV.dir/Logger.cpp.o.provides.build
.PHONY : glslang/SPIRV/CMakeFiles/SPIRV.dir/Logger.cpp.o.provides

glslang/SPIRV/CMakeFiles/SPIRV.dir/Logger.cpp.o.provides.build: glslang/SPIRV/CMakeFiles/SPIRV.dir/Logger.cpp.o


glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvBuilder.cpp.o: glslang/SPIRV/CMakeFiles/SPIRV.dir/flags.make
glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvBuilder.cpp.o: /home/caleb/.cargo/registry/src/github.com-1ecc6299db9ec823/shaderc-sys-0.6.2/build/glslang/SPIRV/SpvBuilder.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvBuilder.cpp.o"
	cd /home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/glslang/SPIRV && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/SPIRV.dir/SpvBuilder.cpp.o -c /home/caleb/.cargo/registry/src/github.com-1ecc6299db9ec823/shaderc-sys-0.6.2/build/glslang/SPIRV/SpvBuilder.cpp

glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvBuilder.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/SPIRV.dir/SpvBuilder.cpp.i"
	cd /home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/glslang/SPIRV && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/caleb/.cargo/registry/src/github.com-1ecc6299db9ec823/shaderc-sys-0.6.2/build/glslang/SPIRV/SpvBuilder.cpp > CMakeFiles/SPIRV.dir/SpvBuilder.cpp.i

glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvBuilder.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/SPIRV.dir/SpvBuilder.cpp.s"
	cd /home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/glslang/SPIRV && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/caleb/.cargo/registry/src/github.com-1ecc6299db9ec823/shaderc-sys-0.6.2/build/glslang/SPIRV/SpvBuilder.cpp -o CMakeFiles/SPIRV.dir/SpvBuilder.cpp.s

glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvBuilder.cpp.o.requires:

.PHONY : glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvBuilder.cpp.o.requires

glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvBuilder.cpp.o.provides: glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvBuilder.cpp.o.requires
	$(MAKE) -f glslang/SPIRV/CMakeFiles/SPIRV.dir/build.make glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvBuilder.cpp.o.provides.build
.PHONY : glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvBuilder.cpp.o.provides

glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvBuilder.cpp.o.provides.build: glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvBuilder.cpp.o


glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvPostProcess.cpp.o: glslang/SPIRV/CMakeFiles/SPIRV.dir/flags.make
glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvPostProcess.cpp.o: /home/caleb/.cargo/registry/src/github.com-1ecc6299db9ec823/shaderc-sys-0.6.2/build/glslang/SPIRV/SpvPostProcess.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvPostProcess.cpp.o"
	cd /home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/glslang/SPIRV && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/SPIRV.dir/SpvPostProcess.cpp.o -c /home/caleb/.cargo/registry/src/github.com-1ecc6299db9ec823/shaderc-sys-0.6.2/build/glslang/SPIRV/SpvPostProcess.cpp

glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvPostProcess.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/SPIRV.dir/SpvPostProcess.cpp.i"
	cd /home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/glslang/SPIRV && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/caleb/.cargo/registry/src/github.com-1ecc6299db9ec823/shaderc-sys-0.6.2/build/glslang/SPIRV/SpvPostProcess.cpp > CMakeFiles/SPIRV.dir/SpvPostProcess.cpp.i

glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvPostProcess.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/SPIRV.dir/SpvPostProcess.cpp.s"
	cd /home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/glslang/SPIRV && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/caleb/.cargo/registry/src/github.com-1ecc6299db9ec823/shaderc-sys-0.6.2/build/glslang/SPIRV/SpvPostProcess.cpp -o CMakeFiles/SPIRV.dir/SpvPostProcess.cpp.s

glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvPostProcess.cpp.o.requires:

.PHONY : glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvPostProcess.cpp.o.requires

glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvPostProcess.cpp.o.provides: glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvPostProcess.cpp.o.requires
	$(MAKE) -f glslang/SPIRV/CMakeFiles/SPIRV.dir/build.make glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvPostProcess.cpp.o.provides.build
.PHONY : glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvPostProcess.cpp.o.provides

glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvPostProcess.cpp.o.provides.build: glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvPostProcess.cpp.o


glslang/SPIRV/CMakeFiles/SPIRV.dir/doc.cpp.o: glslang/SPIRV/CMakeFiles/SPIRV.dir/flags.make
glslang/SPIRV/CMakeFiles/SPIRV.dir/doc.cpp.o: /home/caleb/.cargo/registry/src/github.com-1ecc6299db9ec823/shaderc-sys-0.6.2/build/glslang/SPIRV/doc.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building CXX object glslang/SPIRV/CMakeFiles/SPIRV.dir/doc.cpp.o"
	cd /home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/glslang/SPIRV && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/SPIRV.dir/doc.cpp.o -c /home/caleb/.cargo/registry/src/github.com-1ecc6299db9ec823/shaderc-sys-0.6.2/build/glslang/SPIRV/doc.cpp

glslang/SPIRV/CMakeFiles/SPIRV.dir/doc.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/SPIRV.dir/doc.cpp.i"
	cd /home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/glslang/SPIRV && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/caleb/.cargo/registry/src/github.com-1ecc6299db9ec823/shaderc-sys-0.6.2/build/glslang/SPIRV/doc.cpp > CMakeFiles/SPIRV.dir/doc.cpp.i

glslang/SPIRV/CMakeFiles/SPIRV.dir/doc.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/SPIRV.dir/doc.cpp.s"
	cd /home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/glslang/SPIRV && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/caleb/.cargo/registry/src/github.com-1ecc6299db9ec823/shaderc-sys-0.6.2/build/glslang/SPIRV/doc.cpp -o CMakeFiles/SPIRV.dir/doc.cpp.s

glslang/SPIRV/CMakeFiles/SPIRV.dir/doc.cpp.o.requires:

.PHONY : glslang/SPIRV/CMakeFiles/SPIRV.dir/doc.cpp.o.requires

glslang/SPIRV/CMakeFiles/SPIRV.dir/doc.cpp.o.provides: glslang/SPIRV/CMakeFiles/SPIRV.dir/doc.cpp.o.requires
	$(MAKE) -f glslang/SPIRV/CMakeFiles/SPIRV.dir/build.make glslang/SPIRV/CMakeFiles/SPIRV.dir/doc.cpp.o.provides.build
.PHONY : glslang/SPIRV/CMakeFiles/SPIRV.dir/doc.cpp.o.provides

glslang/SPIRV/CMakeFiles/SPIRV.dir/doc.cpp.o.provides.build: glslang/SPIRV/CMakeFiles/SPIRV.dir/doc.cpp.o


glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvTools.cpp.o: glslang/SPIRV/CMakeFiles/SPIRV.dir/flags.make
glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvTools.cpp.o: /home/caleb/.cargo/registry/src/github.com-1ecc6299db9ec823/shaderc-sys-0.6.2/build/glslang/SPIRV/SpvTools.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building CXX object glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvTools.cpp.o"
	cd /home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/glslang/SPIRV && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/SPIRV.dir/SpvTools.cpp.o -c /home/caleb/.cargo/registry/src/github.com-1ecc6299db9ec823/shaderc-sys-0.6.2/build/glslang/SPIRV/SpvTools.cpp

glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvTools.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/SPIRV.dir/SpvTools.cpp.i"
	cd /home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/glslang/SPIRV && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/caleb/.cargo/registry/src/github.com-1ecc6299db9ec823/shaderc-sys-0.6.2/build/glslang/SPIRV/SpvTools.cpp > CMakeFiles/SPIRV.dir/SpvTools.cpp.i

glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvTools.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/SPIRV.dir/SpvTools.cpp.s"
	cd /home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/glslang/SPIRV && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/caleb/.cargo/registry/src/github.com-1ecc6299db9ec823/shaderc-sys-0.6.2/build/glslang/SPIRV/SpvTools.cpp -o CMakeFiles/SPIRV.dir/SpvTools.cpp.s

glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvTools.cpp.o.requires:

.PHONY : glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvTools.cpp.o.requires

glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvTools.cpp.o.provides: glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvTools.cpp.o.requires
	$(MAKE) -f glslang/SPIRV/CMakeFiles/SPIRV.dir/build.make glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvTools.cpp.o.provides.build
.PHONY : glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvTools.cpp.o.provides

glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvTools.cpp.o.provides.build: glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvTools.cpp.o


glslang/SPIRV/CMakeFiles/SPIRV.dir/disassemble.cpp.o: glslang/SPIRV/CMakeFiles/SPIRV.dir/flags.make
glslang/SPIRV/CMakeFiles/SPIRV.dir/disassemble.cpp.o: /home/caleb/.cargo/registry/src/github.com-1ecc6299db9ec823/shaderc-sys-0.6.2/build/glslang/SPIRV/disassemble.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Building CXX object glslang/SPIRV/CMakeFiles/SPIRV.dir/disassemble.cpp.o"
	cd /home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/glslang/SPIRV && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/SPIRV.dir/disassemble.cpp.o -c /home/caleb/.cargo/registry/src/github.com-1ecc6299db9ec823/shaderc-sys-0.6.2/build/glslang/SPIRV/disassemble.cpp

glslang/SPIRV/CMakeFiles/SPIRV.dir/disassemble.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/SPIRV.dir/disassemble.cpp.i"
	cd /home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/glslang/SPIRV && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/caleb/.cargo/registry/src/github.com-1ecc6299db9ec823/shaderc-sys-0.6.2/build/glslang/SPIRV/disassemble.cpp > CMakeFiles/SPIRV.dir/disassemble.cpp.i

glslang/SPIRV/CMakeFiles/SPIRV.dir/disassemble.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/SPIRV.dir/disassemble.cpp.s"
	cd /home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/glslang/SPIRV && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/caleb/.cargo/registry/src/github.com-1ecc6299db9ec823/shaderc-sys-0.6.2/build/glslang/SPIRV/disassemble.cpp -o CMakeFiles/SPIRV.dir/disassemble.cpp.s

glslang/SPIRV/CMakeFiles/SPIRV.dir/disassemble.cpp.o.requires:

.PHONY : glslang/SPIRV/CMakeFiles/SPIRV.dir/disassemble.cpp.o.requires

glslang/SPIRV/CMakeFiles/SPIRV.dir/disassemble.cpp.o.provides: glslang/SPIRV/CMakeFiles/SPIRV.dir/disassemble.cpp.o.requires
	$(MAKE) -f glslang/SPIRV/CMakeFiles/SPIRV.dir/build.make glslang/SPIRV/CMakeFiles/SPIRV.dir/disassemble.cpp.o.provides.build
.PHONY : glslang/SPIRV/CMakeFiles/SPIRV.dir/disassemble.cpp.o.provides

glslang/SPIRV/CMakeFiles/SPIRV.dir/disassemble.cpp.o.provides.build: glslang/SPIRV/CMakeFiles/SPIRV.dir/disassemble.cpp.o


# Object files for target SPIRV
SPIRV_OBJECTS = \
"CMakeFiles/SPIRV.dir/GlslangToSpv.cpp.o" \
"CMakeFiles/SPIRV.dir/InReadableOrder.cpp.o" \
"CMakeFiles/SPIRV.dir/Logger.cpp.o" \
"CMakeFiles/SPIRV.dir/SpvBuilder.cpp.o" \
"CMakeFiles/SPIRV.dir/SpvPostProcess.cpp.o" \
"CMakeFiles/SPIRV.dir/doc.cpp.o" \
"CMakeFiles/SPIRV.dir/SpvTools.cpp.o" \
"CMakeFiles/SPIRV.dir/disassemble.cpp.o"

# External object files for target SPIRV
SPIRV_EXTERNAL_OBJECTS =

glslang/SPIRV/libSPIRV.a: glslang/SPIRV/CMakeFiles/SPIRV.dir/GlslangToSpv.cpp.o
glslang/SPIRV/libSPIRV.a: glslang/SPIRV/CMakeFiles/SPIRV.dir/InReadableOrder.cpp.o
glslang/SPIRV/libSPIRV.a: glslang/SPIRV/CMakeFiles/SPIRV.dir/Logger.cpp.o
glslang/SPIRV/libSPIRV.a: glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvBuilder.cpp.o
glslang/SPIRV/libSPIRV.a: glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvPostProcess.cpp.o
glslang/SPIRV/libSPIRV.a: glslang/SPIRV/CMakeFiles/SPIRV.dir/doc.cpp.o
glslang/SPIRV/libSPIRV.a: glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvTools.cpp.o
glslang/SPIRV/libSPIRV.a: glslang/SPIRV/CMakeFiles/SPIRV.dir/disassemble.cpp.o
glslang/SPIRV/libSPIRV.a: glslang/SPIRV/CMakeFiles/SPIRV.dir/build.make
glslang/SPIRV/libSPIRV.a: glslang/SPIRV/CMakeFiles/SPIRV.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_9) "Linking CXX static library libSPIRV.a"
	cd /home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/glslang/SPIRV && $(CMAKE_COMMAND) -P CMakeFiles/SPIRV.dir/cmake_clean_target.cmake
	cd /home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/glslang/SPIRV && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/SPIRV.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
glslang/SPIRV/CMakeFiles/SPIRV.dir/build: glslang/SPIRV/libSPIRV.a

.PHONY : glslang/SPIRV/CMakeFiles/SPIRV.dir/build

glslang/SPIRV/CMakeFiles/SPIRV.dir/requires: glslang/SPIRV/CMakeFiles/SPIRV.dir/GlslangToSpv.cpp.o.requires
glslang/SPIRV/CMakeFiles/SPIRV.dir/requires: glslang/SPIRV/CMakeFiles/SPIRV.dir/InReadableOrder.cpp.o.requires
glslang/SPIRV/CMakeFiles/SPIRV.dir/requires: glslang/SPIRV/CMakeFiles/SPIRV.dir/Logger.cpp.o.requires
glslang/SPIRV/CMakeFiles/SPIRV.dir/requires: glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvBuilder.cpp.o.requires
glslang/SPIRV/CMakeFiles/SPIRV.dir/requires: glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvPostProcess.cpp.o.requires
glslang/SPIRV/CMakeFiles/SPIRV.dir/requires: glslang/SPIRV/CMakeFiles/SPIRV.dir/doc.cpp.o.requires
glslang/SPIRV/CMakeFiles/SPIRV.dir/requires: glslang/SPIRV/CMakeFiles/SPIRV.dir/SpvTools.cpp.o.requires
glslang/SPIRV/CMakeFiles/SPIRV.dir/requires: glslang/SPIRV/CMakeFiles/SPIRV.dir/disassemble.cpp.o.requires

.PHONY : glslang/SPIRV/CMakeFiles/SPIRV.dir/requires

glslang/SPIRV/CMakeFiles/SPIRV.dir/clean:
	cd /home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/glslang/SPIRV && $(CMAKE_COMMAND) -P CMakeFiles/SPIRV.dir/cmake_clean.cmake
.PHONY : glslang/SPIRV/CMakeFiles/SPIRV.dir/clean

glslang/SPIRV/CMakeFiles/SPIRV.dir/depend:
	cd /home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/caleb/.cargo/registry/src/github.com-1ecc6299db9ec823/shaderc-sys-0.6.2/build /home/caleb/.cargo/registry/src/github.com-1ecc6299db9ec823/shaderc-sys-0.6.2/build/glslang/SPIRV /home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build /home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/glslang/SPIRV /home/caleb/Projects/emu/docs/debug/build/shaderc-sys-cef2278ad5b6e469/out/build/glslang/SPIRV/CMakeFiles/SPIRV.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : glslang/SPIRV/CMakeFiles/SPIRV.dir/depend

