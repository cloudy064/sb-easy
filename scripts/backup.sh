#!/bin/sh
# Online backup of the sb-easy SQLite database, with gzip + rotation.
# Safe to run while the container is live (uses SQLite's online .backup).
#
# Env:
#   SB_EASY_DB          path to the DB     (default: ./data/sb-easy.db)
#   SB_EASY_BACKUP_DIR  output directory   (default: ./backups)
#   SB_EASY_BACKUP_KEEP how many to keep   (default: 14)
#
# Cron example (daily 03:30, from the compose project dir):
#   30 3 * * * cd /work/workspace/github/sb-easy && ./scripts/backup.sh >> backups/backup.log 2>&1
set -e

DB="${SB_EASY_DB:-./data/sb-easy.db}"
DEST="${SB_EASY_BACKUP_DIR:-./backups}"
KEEP="${SB_EASY_BACKUP_KEEP:-14}"

[ -f "$DB" ] || { echo "DB not found: $DB" >&2; exit 1; }
mkdir -p "$DEST"

TS=$(date +%Y%m%d-%H%M%S)
OUT="$DEST/sb-easy-$TS.db"
sqlite3 "$DB" ".backup '$OUT'"
gzip -f "$OUT"

# Rotation: keep the newest $KEEP, delete older.
ls -1t "$DEST"/sb-easy-*.db.gz 2>/dev/null | tail -n +$((KEEP + 1)) | xargs -r rm -f
echo "backup written: $OUT.gz"
