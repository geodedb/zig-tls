{
  description = "QUIC v1 transport implementation in Zig";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    flake-utils.url = "github:numtide/flake-utils";
    dev-env.url = "github:spyderorg/dev-env";
  };

  outputs =
    {
      self,
      nixpkgs,
      dev-env,
      flake-utils,
      ...
    }:
    let

      flakeForSystem =
        nixpkgs: system:
        let
          pkgs = import nixpkgs {
            inherit system;
            config = { allowUnfree = true; };
          };

          # Python environment for geodetestlab and client test harness
          pythonWithPackages = pkgs.python3.withPackages (ps: with ps; [
            pip
            cffi
            setuptools
            wheel
            typer
            pydantic
            rich
            jmespath
            psutil
            keyring
            pyyaml
            pytest
            mypy
            black
            isort
            flake8
            aioquic
            cryptography
            pyopenssl
            service-identity
            python-lsp-server
          ]);

          zigPkg = dev-env.packages.${system}.zigPackages;

          # Build quic packages
          quicPkg = pkgs.callPackage ./nix/quic.nix {
            zig = zigPkg;
            optimize = "ReleaseSafe";
          };
          
          quicDebugPkg = pkgs.callPackage ./nix/quic.nix {
            zig = zigPkg;
            optimize = "Debug";
          };
          
          # Single source of truth for the development environment packages
          devShellPackages = with pkgs; [
            zigPkg
          ];
        in
        {
          packages = {
            quic = quicPkg;
            quic-debug = quicDebugPkg;
            default = quicPkg;
          };
          devShell = pkgs.mkShell {
            shellHook = ''
              # --- Python path --------------------------------------------------------------
              # Use the Python 3 environment with all required packages (cffi, aioquic, etc)
              # This ensures we use Python 3.12 with cffi instead of the system Python 3.13
              export PATH="${pythonWithPackages}/bin:$PATH"

              # Reset PYTHONPATH safely, then prepend the env's site-packages if it exists.
              export PYTHONPATH=''${PYTHONPATH:-""}
              if [ -d "${pythonWithPackages}/${pythonWithPackages.sitePackages}" ]; then
                export PYTHONPATH="${pythonWithPackages}/${pythonWithPackages.sitePackages}:$PYTHONPATH"
              fi

              # --- C/C++ compiler flags for glibc -------------------------------------------
              # Required for building C/C++ projects (like quiche's BoringSSL) with proper glibc headers
              # Use -idirafter to append glibc includes after C++ stdlib, avoiding #include_next issues
              export NIX_CFLAGS_COMPILE="''${NIX_CFLAGS_COMPILE:-""}"
              export NIX_CXXFLAGS_COMPILE="''${NIX_CXXFLAGS_COMPILE:-""}"
              export NIX_LDFLAGS="''${NIX_LDFLAGS:-""} -L${pkgs.glibc}/lib -L${pkgs.gcc.cc.lib}/lib -L${pkgs.libffi}/lib"

              # Set CFLAGS/CXXFLAGS for CMake-based builds (e.g., BoringSSL in quiche)
              # CMake doesn't inherit Nix's wrapper flags, so we need to set them explicitly
              export CFLAGS="''${CFLAGS:-""}"
              export CXXFLAGS="''${CXXFLAGS:-""}"
              export LDFLAGS="''${LDFLAGS:-""} -L${pkgs.glibc}/lib -L${pkgs.gcc.cc.lib}/lib -L${pkgs.libffi}/lib"

              # Ensure libffi is in the library path for cffi
              export LD_LIBRARY_PATH="${pkgs.libffi}/lib:''${LD_LIBRARY_PATH:-""}"

              # --- GitHub CLI auth ----------------------------------------------------------
              # If not authenticated, try token-based login from ~/.github_token
              ${pkgs.gh}/bin/gh auth status >/dev/null 2>&1 || \
                ${pkgs.gh}/bin/gh auth login --with-token < "$HOME/.github_token" 2>/dev/null || \
                warn "GitHub CLI not authenticated, some features may not work"
              
              # Export a real token value (command substitution was missing before)
              export GITHUB_TOKEN="$(${pkgs.gh}/bin/gh auth token 2>/dev/null || true)"
              
              # --- Vault login & secret retrieval ------------------------------------------
              export VAULT_ADDR="https://pki.devnw.com"
              
              # Use the pinned vault binary consistently
              if ! ${pkgs.vault}/bin/vault token lookup -no-print >/dev/null 2>&1; then
                # Use the GH token we just exported
                ${pkgs.vault}/bin/vault login -no-print -method=github token="''${GITHUB_TOKEN}" \
                  >/dev/null 2>&1 || warn "Vault login failed"
              fi
              
              # Pull secrets (command substitutions were previously double-$-escaped)
              OPENAI_API_KEY="$(${pkgs.vault}/bin/vault kv get -mount=secret -field=token /dev/openai/actions-primary 2>/dev/null || echo "")"
              export OPENAI_API_KEY
              
              CACHIX_AUTH_TOKEN="$(${pkgs.vault}/bin/vault kv get -mount=secret -field=token /cicd/gh/cachix 2>/dev/null || echo "")"
              export CACHIX_AUTH_TOKEN
              
              # --- Nix configuration & Cachix ----------------------------------------------
              # Use ''${VAR} to avoid Nix interpolation while still expanding in bash.
              NIX_CONFIG="experimental-features = nix-command flakes
              access-tokens = github.com=''${GITHUB_TOKEN}
              trusted-users = root $(whoami)"
              export NIX_CONFIG
              
              # Best-effort: add current user as trusted in /etc/nix/nix.conf (may require sudo)
              if ! grep -q "trusted-users.*$(whoami)" /etc/nix/nix.conf 2>/dev/null; then
                warn "Adding $(whoami) as trusted user for Nix..."
                echo "trusted-users = root $(whoami)" | sudo tee -a /etc/nix/nix.conf >/dev/null || true
                sudo pkill nix-daemon 2>/dev/null || true
                sleep 2
              fi
              
              # Cachix auth & binary cache (use pinned cachix)
              if [ -n "''${CACHIX_AUTH_TOKEN-}" ]; then
                ${pkgs.cachix}/bin/cachix authtoken "''${CACHIX_AUTH_TOKEN}" >/dev/null 2>&1 || true
                ${pkgs.cachix}/bin/cachix use spyder >/dev/null 2>&1 || warn "Could not configure Cachix binary cache"
              fi
            '';
            env = { };
            packages =
              (with dev-env.packages.${system}; [
                goPackages
                zigPackages
                commonPackages
              ])
              ++ (with pkgs; [
                toybox
                file
                tcpdump
                tshark
                pythonWithPackages

                  # Rust toolchain for client tests
                  rustc
                  cargo
                  rustfmt
                  rust-analyzer
                  clippy
                  boringssl
                  glibc
                  glibc.dev
                  gcc.cc.lib
                  libev
                  libffi

                  # Debugging and analysis
                  gdb
                  valgrind
                  strace

                  # Network tools
                  tcpdump
                  wireshark-cli
                  netcat-gnu
              ]);
          };
        };
    in
    flake-utils.lib.eachDefaultSystem (system: flakeForSystem nixpkgs system);

  nixConfig = {
    extra-substituters = [ "https://spyder.cachix.org" ];
    extra-trusted-public-keys = [
      "spyder.cachix.org-1:xZG2a8INH6yNyOAwtN2Ojjys0GO9D1pXEe3PNriT04E="
    ];
  };
}
