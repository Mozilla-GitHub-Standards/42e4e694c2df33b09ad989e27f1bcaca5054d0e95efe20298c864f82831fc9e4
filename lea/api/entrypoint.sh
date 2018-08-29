#!/bin/bash

LEA_EP="$0"
echo "this script is: $LEA_EP"

LEA_UID=${LEA_UID:-0}
LEA_GID=${LEA_GID:-0}
LEA_USER=${LEA_USER:-root}
LEA_APP_TIMEOUT=${LEA_APP_TIMEOUT:-120}
LEA_APP_PORT=${LEA_APP_PORT:-8000}
LEA_APP_WORKERS=${LEA_APP_WORKERS:-2}
LEA_APP_MODULE=${LEA_APP_MODULE:-main:app}
CMD="python3 -u /usr/local/bin/gunicorn -t $LEA_APP_TIMEOUT -w $LEA_APP_WORKERS -b :$LEA_APP_PORT $LEA_APP_MODULE"

if ! getent passwd "$LEA_USER" 2>/dev/null; then
    echo "creating user $LEA_USER with $LEA_UID:$LEA_GID"
    groupadd --gid "$LEA_GID" "$LEA_USER"
    useradd --uid "$LEA_UID" --gid "$LEA_GID" --shell /bin/bash --no-create-home "$LEA_USER"
    echo -e "\n$LEA_USER   ALL=(ALL) NOPASSWD: ALL\n" > /etc/sudoers
    chown -R "$LEA_USER:$LEA_USER" /usr/src/app/
fi

echo "executing \"$CMD\" as $LEA_USER"
exec su -c "$CMD" "$LEA_USER"
