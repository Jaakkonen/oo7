{
  description = "OO7 - Secret Service provider";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    let
      # NixOS module (system-agnostic)
      nixosModule = import ./nixos-module.nix;
    in
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" ];
        };

        oo7-daemon = pkgs.rustPlatform.buildRustPackage {
          pname = "oo7-daemon";
          version = "0.6.0";

          src = ./.;

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          nativeBuildInputs = with pkgs; [
            pkg-config
            rustToolchain
          ];

          buildInputs = with pkgs; [
            gpgme
            libgpg-error
            libnotify
            dbus
          ];

          # Build only the server package
          cargoBuildFlags = [ "--package" "oo7-daemon" ];

          # Skip tests during build (can be run separately)
          doCheck = false;

          # Install D-Bus service file
          postInstall = ''
            mkdir -p $out/share/dbus-1/services
            cat > $out/share/dbus-1/services/org.freedesktop.secrets.service << EOF
            [D-BUS Service]
            Name=org.freedesktop.secrets
            Exec=$out/bin/oo7-daemon
            SystemdService=oo7-daemon.service
            EOF
          '';

          meta = with pkgs.lib; {
            description = "Secret Service provider with GPG/Yubikey support";
            homepage = "https://github.com/bilelmoussaoui/oo7";
            license = licenses.mit;
            maintainers = [ ];
          };
        };
      in
      {
        packages = {
          default = oo7-daemon;
          oo7-daemon = oo7-daemon;
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            # Rust toolchain
            rustToolchain

            # GPG dependencies for Yubikey support
            gpgme
            libgpg-error
            pkg-config

            # GPG tools
            gnupg

            # Notification support
            libnotify
            dbus

            # Development tools
            git
          ];

          shellHook = ''
            export PKG_CONFIG_PATH="${pkgs.gpgme.dev}/lib/pkgconfig:${pkgs.libgpg-error.dev}/lib/pkgconfig:$PKG_CONFIG_PATH"
            export DBUS_SESSION_BUS_ADDRESS="''${DBUS_SESSION_BUS_ADDRESS:-unix:path=/run/user/$(id -u)/bus}"

            # Set up systemd user service to use debug build (in temporary /run/)
            RUNTIME_DIR="/run/user/$(id -u)"
            OVERRIDE_DIR="$RUNTIME_DIR/systemd/user/oo7-daemon.service.d"
            OVERRIDE_FILE="$OVERRIDE_DIR/override.conf"
            DBUS_SERVICE_DIR="$RUNTIME_DIR/dbus-1/services"
            DBUS_SERVICE_FILE="$DBUS_SERVICE_DIR/org.freedesktop.secrets.service"
            PROJECT_DIR="$(pwd)"

            mkdir -p "$OVERRIDE_DIR" "$DBUS_SERVICE_DIR"

            # Create systemd drop-in override pointing to debug build with trace logging
            # This overrides the ExecStart from /etc/systemd/user/oo7-daemon.service
            cat > "$OVERRIDE_FILE" << 'OVERRIDEEOF'
[Service]
# Clear the ExecStart from the base unit
ExecStart=
# Set new ExecStart pointing to debug build with --replace flag
ExecStart=PROJECT_DIR_PLACEHOLDER/target/debug/oo7-daemon --replace
# Enable trace logging (logs visible via: journalctl --user -u oo7-daemon -f)
Environment=RUST_LOG=trace
Environment=RUST_BACKTRACE=1
OVERRIDEEOF
            sed -i "s|PROJECT_DIR_PLACEHOLDER|$PROJECT_DIR|g" "$OVERRIDE_FILE"

            # Create D-Bus service file pointing to debug build
            cat > "$DBUS_SERVICE_FILE" << 'DBUSEOF'
[D-BUS Service]
Name=org.freedesktop.secrets
Exec=PROJECT_DIR_PLACEHOLDER/target/debug/oo7-daemon
SystemdService=oo7-daemon.service
DBUSEOF
            sed -i "s|PROJECT_DIR_PLACEHOLDER|$PROJECT_DIR|g" "$DBUS_SERVICE_FILE"

            # Reload systemd to pick up changes
            systemctl --user daemon-reload 2>/dev/null || true

            # Automatically restart the service if it's running
            if systemctl --user is-active --quiet oo7-daemon; then
              systemctl --user restart oo7-daemon 2>/dev/null || true
            fi

            echo "Dev mode: debug build at $PROJECT_DIR/target/debug/oo7-daemon"
            if gpg --card-status &>/dev/null; then
              echo "Yubikey detected"
            fi

            # Helper to run daemon in development mode
            oo7-dev-daemon() {
              pkill -u $(id -u) -f oo7-daemon || true
              sleep 1
              RUST_LOG=oo7_daemon=debug,oo7=debug \
              cargo run --package oo7-daemon -- --replace
            }

            # Helper to run the test
            oo7-test() {
              cargo run --example yubikey_test --features tokio
            }

            export -f oo7-dev-daemon
            export -f oo7-test
          '';
        };
      }
    ) // {
      # Export NixOS module at top level (system-agnostic)
      nixosModules.default = nixosModule;
    };
}
