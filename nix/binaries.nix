{
  pkgs ? import <nixpkgs> { },
  version ? "dev",
}:
let
  inherit (pkgs.lib) cleanSource cleanSourceWith;
in
pkgs.buildGoModule {
  pname = "chihiro";
  version = "${version}";

  src = cleanSourceWith {
    filter =
      name: _:
      !(
        (baseNameOf name) == "Dockerfile"
        || (baseNameOf name) == "Makefile"
        || (baseNameOf name) == "README.md"
        || (baseNameOf name) == "PROJECT"
        || (baseNameOf name) == "config"
        || (baseNameOf name) == "conf"
        || (baseNameOf name) == "nix"
      );
    src = cleanSource ../.;
  };
  ldflags = [
    "-s"
    "-w"
    "-X github.com/Bealvio/chihiro/cmd.version=${version}"
  ];

  vendorHash = "sha256-bEkgJxBwjmNM6TvQp/3zXnXxoHiXC+6C+Y4naskj4/g=";

  doCheck = true;

  meta = with pkgs.lib; {
    description = "$pname; version: $version";
    homepage = "http://github.com/banh-canh/$pname";
    license = licenses.asl20;
    platforms = platforms.linux;
    mainProgram = "$pname";
  };
}
