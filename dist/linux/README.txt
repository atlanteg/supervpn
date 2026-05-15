supervpn — Linux Server
=======================

Files:
  supervpn-server          — server binary (linux/amd64)
  server.toml.example      — example config; copy to server.toml and edit
  supervpn-server.service  — systemd unit file

Quick start
-----------
1. Copy files to server:
     scp supervpn-server server.toml.example supervpn-server.service root@YOUR_SERVER:/opt/supervpn/

2. Generate password hashes for each user:
     ./supervpn-server hashpw mypassword
     # outputs: $2a$10$...

3. Create config:
     cp server.toml.example server.toml
     nano server.toml   # set listen addresses, paste hashes

4. Open firewall:
     ufw allow 5555/udp
     ufw allow 443/tcp   # TLS/TCP fallback

5. Run directly:
     sudo ./supervpn-server -config server.toml

6. Or install as systemd service:
     sudo cp supervpn-server.service /etc/systemd/system/
     sudo systemctl daemon-reload
     sudo systemctl enable --now supervpn-server
     sudo journalctl -fu supervpn-server

Status API:
     curl http://127.0.0.1:9090/status

Kick a client (blocks login for 5 minutes):
     curl -X POST http://127.0.0.1:9090/api/hubs/1/kick/{session_id}
     # session_id is shown in /status and in server logs
