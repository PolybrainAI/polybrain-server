set shell := ["bash", "-cu"]

start:
    @echo "Running new server"
    just stop
    cargo run --release > server.log 2>&1 & echo $! > .server-pid

stop:
    @echo "Killing existing server"
    [ ! -f .server-pid ] || { kill $(cat .server-pid) 2>/dev/null && rm .server-pid; } 