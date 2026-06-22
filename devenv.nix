{
  pkgs,
  lib,
  ...
}:
{
  packages = with pkgs; [
    go
    golangci-lint
    air
  ];

  services.redis = {
    enable = true;
    port = 6379;
    bind = "127.0.0.1";
  };

  env.CHIHIRO_REDIS_ADDR = "127.0.0.1:6379";

  enterShell = ''
    echo ""
    echo "Chihiro development environment loaded"
    echo ""
    echo "  Redis:  127.0.0.1:6379"
    echo "  Config: config.yaml"
    echo ""
    echo "Run with:"
    echo "  CHIHIRO_OIDC_CLIENT_SECRET=xxx CHIHIRO_SESSION_KEY=xxx go run . serve --config=config.yaml"
    echo ""
  '';
}
