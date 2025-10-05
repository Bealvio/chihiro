{
  pkgs ? import <nixpkgs> { },
  dockerVersion ? "0.0.0",
  imageName ? "zot.bealv.io/public/chihiro",
}:
let
  binaries = pkgs.callPackage ./binaries.nix { version = dockerVersion; };
  makeDummyImage = {
    fakeRootCommands = ''
      ln -s var/run run
      ln -s bin/${binaries.pname} chihiro
    '';
    name = "${imageName}";
    contents = [
      binaries
      pkgs.dockerTools.caCertificates
      pkgs.openssl
      pkgs.cacert
      (pkgs.dockerTools.fakeNss.override {
        extraPasswdLines = [
          "nixbld:x:${toString 1001}:${toString 0}:Build user:/home/${binaries.pname}:/noshell"
        ];
        extraGroupLines = [ "nixbld:!:${toString 1001}:" ];
      })
    ];

    config = {
      User = "1001:0";
      Entrypoint = [ "/chihiro" ];
      Env = [
        "NIX_SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
        "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
      ];
    };
  };
  imageDummy = pkgs.dockerTools.streamLayeredImage {
    inherit (makeDummyImage) fakeRootCommands;
    inherit (makeDummyImage) name;
    inherit (makeDummyImage) contents;
    inherit (makeDummyImage) config;
    tag = "${dockerVersion}";
  };
in
pkgs.dockerTools.streamLayeredImage {
  inherit (makeDummyImage) fakeRootCommands;
  tag = imageDummy.imageTag;
  inherit (makeDummyImage) name;
  inherit (makeDummyImage) contents;
  inherit (makeDummyImage) config;
}
