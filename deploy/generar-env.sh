#!/usr/bin/env bash
# Crea deploy/.env con secretos y contraseñas aleatorias que no están en ningún repositorio.
#
#   ./generar-env.sh <dominio-del-backend> <url-del-frontend>
#   ./generar-env.sh api.segsoft.example https://app.segsoft.example
#
# Las cuentas son las que usa el guion de pruebas: admin, auditor, dev y usuario.
set -euo pipefail
cd "$(dirname "$0")"

if [[ $# -ne 2 ]]; then
    echo "Uso: $0 <dominio-del-backend> <url-del-frontend>" >&2
    echo "Ej.: $0 api.segsoft.example https://app.segsoft.example" >&2
    exit 2
fi
API_DOMAIN=$1
FRONTEND_ORIGIN=${2%/}

if [[ -e .env ]]; then
    echo "Ya existe deploy/.env; no se sobrescribe (bórralo a mano si de verdad quieres regenerarlo)." >&2
    exit 1
fi

# Lee un bloque fijo de /dev/urandom: con "tr </dev/urandom | head" tr muere por SIGPIPE y,
# con pipefail, el script se aborta en silencio.
random() { head -c 4096 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9' | cut -c "1-$1"; }

declare -A ROLE=([admin]=SECURITY_ADMIN [auditor]=AUDITOR [dev]=DEVELOPER [usuario]=DEVELOPER)
declare -A PASSWORD
ACCOUNTS=""
for user in admin auditor dev usuario; do
    PASSWORD[$user]=$(random 16)
    ACCOUNTS+="${ACCOUNTS:+;}$user:${ROLE[$user]}:${PASSWORD[$user]}"
done

umask 077
cat > .env <<EOF
# Generado por generar-env.sh el $(date -u +%Y-%m-%dT%H:%MZ). No lo subas a ningún repositorio.
API_DOMAIN=$API_DOMAIN
FRONTEND_ORIGIN=$FRONTEND_ORIGIN
DB_PASSWORD=$(random 32)
JWT_SECRET=$(random 48)
INTERNAL_SERVICE_TOKEN=$(random 48)
SEGSOFT_ACCOUNTS=$ACCOUNTS
EOF

echo "Creado deploy/.env (permisos 600). Cuentas para los probadores:"
echo
printf '  %-8s %-15s %s\n' "Usuario" "Rol" "Contraseña"
for user in admin auditor dev usuario; do
    printf '  %-8s %-15s %s\n' "$user" "${ROLE[$user]}" "${PASSWORD[$user]}"
done
echo
echo "Quedan guardadas en SEGSOFT_ACCOUNTS dentro de deploy/.env."
