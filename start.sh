#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
#  NetSentry — Dev launcher
#  Starts API + React dashboard in parallel
# ─────────────────────────────────────────────────────────────
set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}"
echo "  ⬡  NETSENTRY — starting dev environment"
echo -e "${NC}"

# Install deps if needed
if [ ! -d "api/node_modules" ]; then
  echo -e "${YELLOW}[API] Installing dependencies...${NC}"
  (cd api && npm install)
fi

if [ ! -d "frontend/node_modules" ]; then
  echo -e "${YELLOW}[Frontend] Installing dependencies...${NC}"
  (cd frontend && npm install)
fi

# Start services
echo -e "${GREEN}[API]      starting on http://localhost:3001${NC}"
(cd api && npm start) &
API_PID=$!

sleep 1   # give API a moment to bind

echo -e "${GREEN}[Frontend] starting on http://localhost:5173${NC}"
(cd frontend && npm run dev) &
FE_PID=$!

echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  Dashboard  → ${GREEN}http://localhost:5173${NC}"
echo -e "  API        → ${GREEN}http://localhost:3001/api/health${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  Press ${YELLOW}Ctrl+C${NC} to stop all services"
echo ""

# Trap Ctrl+C and kill both
trap "echo ''; echo 'Stopping...'; kill $API_PID $FE_PID 2>/dev/null; exit 0" INT TERM

wait
