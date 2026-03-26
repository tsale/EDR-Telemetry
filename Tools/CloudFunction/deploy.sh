#!/bin/bash
# Deploy the EDR Telemetry Updater Cloud Function to GCP.
#
# Prerequisites:
#   - gcloud CLI installed and authenticated
#   - .env.yaml present (copy from .env.yaml.example and fill in values)
#   - Cloud Functions + Cloud Build APIs enabled

set -e

FUNCTION_NAME="edr-telemetry-updater"
REGION="us-central1"
RUNTIME="python313"
ENTRY_POINT="main"
TIMEOUT="300s"
MEMORY="512M"
PROJECT="edr-telemetry-project"

# ── Checks ────────────────────────────────────────────────────────────────────

if ! command -v gcloud &>/dev/null; then
  echo "❌ gcloud CLI not found. Install it from https://cloud.google.com/sdk/docs/install"
  exit 1
fi

if [ ! -f ".env.yaml" ]; then
  echo "❌ .env.yaml not found."
  echo "   Copy .env.yaml.example → .env.yaml and fill in your credentials."
  exit 1
fi

if grep -q "<your-" .env.yaml; then
  echo "⚠️  .env.yaml still contains placeholder values. Update before deploying."
  read -rp "Continue anyway? (y/N): " reply
  [[ "$reply" =~ ^[Yy]$ ]] || exit 1
fi

echo "🚀 Deploying ${FUNCTION_NAME} (project: ${PROJECT}, region: ${REGION})"

# ── Enable required GCP APIs ──────────────────────────────────────────────────

gcloud services enable cloudfunctions.googleapis.com cloudbuild.googleapis.com logging.googleapis.com \
  --project="${PROJECT}"

# ── Deploy ────────────────────────────────────────────────────────────────────

gcloud functions deploy "${FUNCTION_NAME}" \
  --gen2 \
  --project="${PROJECT}" \
  --runtime="${RUNTIME}" \
  --region="${REGION}" \
  --source=. \
  --entry-point="${ENTRY_POINT}" \
  --trigger-http \
  --allow-unauthenticated \
  --timeout="${TIMEOUT}" \
  --memory="${MEMORY}" \
  --env-vars-file=.env.yaml \
  --max-instances=10 \
  --min-instances=0

# ── Post-deploy info ──────────────────────────────────────────────────────────

FUNCTION_URL=$(gcloud functions describe "${FUNCTION_NAME}" \
  --project="${PROJECT}" \
  --region="${REGION}" \
  --format="value(serviceConfig.uri)")

echo ""
echo "✅ Deployed successfully"
echo "   URL: ${FUNCTION_URL}"
echo ""
echo "Manual trigger examples:"
echo "  All platforms:  curl -X POST \"${FUNCTION_URL}?platform=all\""
echo "  Windows only:   curl -X POST \"${FUNCTION_URL}?platform=windows\""
echo "  Linux only:     curl -X POST \"${FUNCTION_URL}?platform=linux\""
echo "  macOS only:     curl -X POST \"${FUNCTION_URL}?platform=macos\""
echo ""
echo "View logs:"
echo "  gcloud functions logs read ${FUNCTION_NAME} --project=${PROJECT} --region=${REGION} --limit=50"
