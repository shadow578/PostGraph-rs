@echo off
set "SMTPBENCH_USER=alice"
set "SMTPBENCH_PASS=hunter2"

start "SMTP Bench Server" cmd /c .\target\release\postgraph_smtp_bench.exe
pause


::smtpbench lb_host=127.0.0.1 port=2525 tls_mode=none recipient=bob@example.com threads=1 messages=1 debug=true

smtpbench lb_host=127.0.0.1 port=2525 tls_mode=none recipient=bob@example.com threads=500 messages=100

