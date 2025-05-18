{ rpkgs ? import <nixpkgs> { crossSystem.config = "riscv64-none-elf"; }, spkgs ? import <nixpkgs>{} }:


rpkgs.mkShell {
    nativeBuildInputs = with spkgs;  [ ];
    buildInputs =  [ ];
    shellHook = ''
        python -m venv .venv
        . .venv/bin/activate
        pip install --quiet -r requirements.txt
    '';
}


