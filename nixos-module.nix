{ config, lib, pkgs, oo7, ... }:

with lib;

let
  cfg = config.services.oo7-daemon;
in
{
  options.services.oo7-daemon = {
    enable = mkEnableOption "OO7 Secret Service daemon with GPG/Yubikey support";

    package = mkOption {
      type = types.package;
      default = oo7.packages.${pkgs.stdenv.hostPlatform.system}.oo7-daemon;
      defaultText = literalExpression "oo7.packages.\${pkgs.stdenv.hostPlatform.system}.oo7-daemon";
      description = "The oo7-daemon package to use.";
    };

    loginKeyring = {
      useGpg = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Enable GPG encryption for the default Login keyring.

          When enabled, the Login keyring will be encrypted with a GPG key
          instead of a password. This allows hardware tokens (like Yubikey)
          to be used for authentication.
        '';
      };

      gpgKeyId = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "FDB4FF661951A129FF2DEEBFC5550EB2423FCEBC";
        description = ''
          GPG key ID to use for encrypting the Login keyring.

          This should be the fingerprint or key ID of a GPG key.
          Required if useGpg is true.
        '';
      };
    };

    disableV1Keyrings = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Disable support for v1 (GNOME Keyring) password-based keyrings.

        When enabled, the daemon will only support GPG-encrypted keyrings
        and will not load or create v1 GNOME password-based keyrings.

        Use the `oo7-cli change-encryption` command to migrate existing
        v1 keyrings to GPG-encrypted format before enabling this option.
      '';
    };
  };

  config = mkIf cfg.enable {
    # Install the daemon package
    environment.systemPackages = [ cfg.package ];

    # Create configuration file if any options are set
    environment.etc."oo7-daemon/config.toml" = mkIf (cfg.loginKeyring.useGpg || cfg.disableV1Keyrings) {
      text = ''
        ${optionalString cfg.loginKeyring.useGpg ''
        [login_keyring]
        use_gpg = true
        gpg_key_id = "${cfg.loginKeyring.gpgKeyId}"
        ''}
        ${optionalString cfg.disableV1Keyrings ''
        disable_v1_keyrings = true
        ''}
      '';
      mode = "0644";
    };

    # Validation
    assertions = [
      {
        assertion = !cfg.loginKeyring.useGpg || cfg.loginKeyring.gpgKeyId != null;
        message = "services.oo7-daemon.loginKeyring.gpgKeyId must be set when useGpg is true";
      }
    ];

    # User systemd service
    systemd.user.services.oo7-daemon = {
      description = "OO7 Secret Service (with GPG/Yubikey support)";
      documentation = [ "https://github.com/bilelmoussaoui/oo7" ];
      after = [ "graphical-session.target" ];
      partOf = [ "graphical-session.target" ];

      serviceConfig = {
        Type = "dbus";
        BusName = "org.freedesktop.secrets";
        ExecStart = "${cfg.package}/bin/oo7-daemon";
        Restart = "on-failure";
        TimeoutStartSec = "30s";
        TimeoutStopSec = "30s";

        # Security settings
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        ProtectClock = true;

        # Allow GPG agent and Yubikey access
        PrivateNetwork = false;
        PrivateDevices = false;
      };

      wantedBy = [ "default.target" ];
    };

    # D-Bus service activation
    services.dbus.packages = [ cfg.package ];
  };
}
