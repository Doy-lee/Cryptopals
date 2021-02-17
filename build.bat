@echo off
setlocal EnableDelayedExpansion

set script_dir=%~dp0
set compilers=cl;clang-cl

for %%a in (!compilers!) do (
    set compiler=%%a
    if "%%a" == "clang-cl" (
        set tag=clang
    ) else (
        set tag=msvc
    )

    set build_dir=!script_dir!build\!tag!
    echo Building with !compiler! to !build_dir!
    mkdir !build_dir! 2>nul
    pushd !build_dir!
        !compiler! /W4 /Z7 /FC /nologo !script_dir!\main.cpp /link
    popd
)
