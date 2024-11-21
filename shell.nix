{ rpkgs ? import <nixpkgs> { crossSystem.config = "riscv64-none-elf"; }, spkgs ? import <nixpkgs>{} }:


rpkgs.mkShell {
    nativeBuildInputs = with spkgs;  [ 
        verilator 
        gcc
        libgcc
        zlib
        nodejs_22
    ];
    buildInputs =  [ ];
    shellHook = ''
        . .venv/bin/activate
    '';
}


