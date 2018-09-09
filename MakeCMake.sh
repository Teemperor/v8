#!/bin/bash
set -e
cp CMakeLists.txt.prefix CMakeLists.txt
find . -name "*.cpp" >> CMakeLists.txt.tmp
find . -name "*.cc" >> CMakeLists.txt.tmp
find . -name "*.c" >> CMakeLists.txt.tmp
find . -name "*.cxx" >> CMakeLists.txt.tmp
find . -name "*.h" >> CMakeLists.txt.tmp
find . -name "*.hpp" >> CMakeLists.txt.tmp
find . -name "*.hh" >> CMakeLists.txt.tmp
cat CMakeLists.txt.tmp \
 | grep -v "/build/" \
 | grep -v ".pass.cpp" \
 | grep -v ".fail.cpp" \
 | sort | uniq \
>> CMakeLists.txt
echo ")" >> CMakeLists.txt
rm CMakeLists.txt.tmp
