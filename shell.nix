{ rpkgs ? import <nixpkgs> { crossSystem.config = "riscv64-none-elf"; }, spkgs ? import <nixpkgs>{} }:


rpkgs.mkShell {
    nativeBuildInputs = with spkgs;  [ ];
    buildInputs =  [ ];
    shellHook = ''
        . .venv/bin/activate
    '';
}


