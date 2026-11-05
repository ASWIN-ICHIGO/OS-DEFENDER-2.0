#!/usr/bin/env bash
# OS-DEFENDER 2.0 — AI engine setup.
# Creates Python venv, installs AI dependencies, trains initial baseline model.
# Usage: ./scripts/setup-ai.sh [--train] [--ollama]
set -euo pipefail

TRAIN=false
SETUP_OLLAMA=false
for arg in "$@"; do
    case "$arg" in
        --train)  TRAIN=true ;;
        --ollama) SETUP_OLLAMA=true ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
AI_DIR="$REPO_ROOT/ai"

info()  { echo -e "\033[1;34m[INFO]\033[0m $*"; }
ok()    { echo -e "\033[1;32m[OK]\033[0m   $*"; }
warn()  { echo -e "\033[1;33m[WARN]\033[0m $*"; }

if [ ! -d "$AI_DIR" ]; then
    echo "Error: ai/ directory not found at $AI_DIR"
    exit 1
fi

# --- 1. Python check ---
PY=""
for candidate in python3 python; do
    if command -v "$candidate" &>/dev/null; then
        PY="$candidate"
        break
    fi
done
if [ -z "$PY" ]; then
    echo "Error: Python 3 not found. Run scripts/setup-deps.sh first."
    exit 1
fi
info "Using $($PY --version)"

# --- 2. Virtual environment ---
cd "$AI_DIR"
if [ ! -d .venv ]; then
    info "Creating virtual environment..."
    $PY -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
info "Upgrading pip..."
pip install -q --upgrade pip

# --- 3. Install dependencies ---
info "Installing AI dependencies..."
pip install -q -e ".[dev]"
ok "Dependencies installed"

# --- 4. Verify installation ---
info "Verifying AI engine..."
python -c "
import sklearn; print(f'  scikit-learn {sklearn.__version__}')
import onnxruntime; print(f'  onnxruntime  {onnxruntime.__version__}')
import numpy; print(f'  numpy        {numpy.__version__}')
"
ok "AI engine verified"

# --- 5. Run tests ---
info "Running AI tests..."
pytest tests/ -q 2>&1 | tail -5
ruff check . 2>&1 | tail -3
ok "All AI tests passed"

# --- 6. Train initial model ---
if [ "$TRAIN" = true ]; then
    info "Training initial baseline model..."
    MODEL_DIR="$REPO_ROOT/models"
    mkdir -p "$MODEL_DIR"
    if [ -f src/os_defender_ai/train.py ]; then
        python -m os_defender_ai.train --output "$MODEL_DIR/anomaly_detector.onnx" 2>&1 || {
            warn "Training script not yet available — model will be trained on first run"
        }
    else
        warn "Training module not found — the agent will train on first run with sufficient data"
    fi
fi

# --- 7. Ollama setup ---
if [ "$SETUP_OLLAMA" = true ]; then
    info "Checking Ollama..."
    if command -v ollama &>/dev/null; then
        ok "Ollama found: $(ollama --version 2>/dev/null || echo 'installed')"
        echo "  Pull a model with: ollama pull llama3.2:1b"
    else
        info "Installing Ollama..."
        curl -fsSL https://ollama.com/install.sh | sh
        ok "Ollama installed"
        echo "  Start with: ollama serve"
        echo "  Pull model: ollama pull llama3.2:1b"
    fi
fi

deactivate

echo ""
echo "==========================================="
info "AI engine setup complete"
echo "==========================================="
echo ""
echo "  Activate venv: cd ai && source .venv/bin/activate"
echo "  Run tests:     pytest && ruff check ."
echo ""
if [ "$TRAIN" = false ]; then
echo "  Train model:   ./scripts/setup-ai.sh --train"
fi
if [ "$SETUP_OLLAMA" = false ]; then
echo "  Setup Ollama:  ./scripts/setup-ai.sh --ollama"
fi
echo ""
