@echo off
set script_dir=%~dp0
set build_dir=%script_dir%\build

mkdir %build_dir% 2>nul
pushd %build_dir%
    cl /W4 /Z7 /FC /nologo %script_dir%\main.cpp /link
popd
