#!/usr/bin/env bash
# ==============================================================================
# Warden: Automated Google Cloud Run & Firestore Deployment Script
# ==============================================================================
set -euo pipefail

PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-$(gcloud config get-value project 2>/dev/null || true)}"
REGION="${GOOGLE_CLOUD_REGION:-us-central1}"
SERVICE_NAME="warden-control-plane"
WARDEN_RUNTIME_MODE="${WARDEN_MODE:-mock}"
TASK_QUEUE="${WARDEN_TASK_QUEUE:-warden-resume}"
ENABLE_CLOUD_TRACE="${WARDEN_ENABLE_CLOUD_TRACE:-true}"
MODEL_ARMOR_TEMPLATE="${WARDEN_MODEL_ARMOR_TEMPLATE:-}"
MODEL_ARMOR_LOCATION="${WARDEN_MODEL_ARMOR_LOCATION:-$REGION}"

if [ -z "$PROJECT_ID" ]; then
    echo "❌ Error: GOOGLE_CLOUD_PROJECT is not set and no default gcloud project found."
    echo "Run: gcloud config set project <YOUR_PROJECT_ID>"
    exit 1
fi

PROJECT_NUMBER="$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')"
if [ -n "${WARDEN_RUNTIME_SERVICE_ACCOUNT:-}" ]; then
    RUNTIME_SERVICE_ACCOUNT="$WARDEN_RUNTIME_SERVICE_ACCOUNT"
else
    RUNTIME_SERVICE_ACCOUNT="warden-runtime@$PROJECT_ID.iam.gserviceaccount.com"
    if ! gcloud iam service-accounts describe "$RUNTIME_SERVICE_ACCOUNT" --project="$PROJECT_ID" >/dev/null 2>&1; then
        echo "--> Creating dedicated runtime service account..."
        gcloud iam service-accounts create "warden-runtime" \
            --display-name="Warden Cloud Run Runtime" \
            --project="$PROJECT_ID"
    fi
fi
TASK_SERVICE_ACCOUNT="${WARDEN_TASK_SERVICE_ACCOUNT:-$RUNTIME_SERVICE_ACCOUNT}"

echo "============================================================================"
echo " 🛡️  Deploying Warden Operator Control Plane to Google Cloud Run"
echo " Project: $PROJECT_ID | Region: $REGION | Service: $SERVICE_NAME"
echo " Runtime mode: $WARDEN_RUNTIME_MODE"
echo "============================================================================"

# 1. Enable Required Google Cloud APIs
echo "--> [1/5] Enabling required Google Cloud APIs (Cloud Run, Firestore, Cloud Tasks, Trace, Artifact Registry)..."
gcloud services enable \
    run.googleapis.com \
    firestore.googleapis.com \
    artifactregistry.googleapis.com \
    cloudbuild.googleapis.com \
    cloudtasks.googleapis.com \
    cloudtrace.googleapis.com \
    modelarmor.googleapis.com \
    iamcredentials.googleapis.com \
    --project="$PROJECT_ID"

echo "--> Creating Cloud Tasks queue '$TASK_QUEUE' if needed..."
gcloud tasks queues describe "$TASK_QUEUE" --location="$REGION" --project="$PROJECT_ID" >/dev/null 2>&1 || \
    gcloud tasks queues create "$TASK_QUEUE" --location="$REGION" --project="$PROJECT_ID"

echo "--> Granting the runtime service account only the state and enqueue permissions it needs..."
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:$RUNTIME_SERVICE_ACCOUNT" \
    --role="roles/datastore.user" \
    --condition=None >/dev/null
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:$RUNTIME_SERVICE_ACCOUNT" \
    --role="roles/cloudtasks.enqueuer" \
    --condition=None >/dev/null
if [ "$ENABLE_CLOUD_TRACE" = "true" ]; then
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:$RUNTIME_SERVICE_ACCOUNT" \
        --role="roles/cloudtrace.agent" \
        --condition=None >/dev/null
fi
if [ -n "$MODEL_ARMOR_TEMPLATE" ]; then
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:$RUNTIME_SERVICE_ACCOUNT" \
        --role="roles/modelarmor.user" \
        --condition=None >/dev/null
fi

# 2. Build Container using Cloud Build
echo "--> [2/5] Building container image with Google Cloud Build..."
gcloud builds submit --tag "gcr.io/$PROJECT_ID/$SERVICE_NAME:latest" --project="$PROJECT_ID"

# 3. Deploy to Cloud Run
echo "--> [3/5] Deploying service to Google Cloud Run..."
DEPLOY_ENV="WARDEN_MODE=$WARDEN_RUNTIME_MODE,GOOGLE_CLOUD_PROJECT=$PROJECT_ID,WARDEN_ENABLE_CLOUD_TRACE=$ENABLE_CLOUD_TRACE"
if [ -n "$MODEL_ARMOR_TEMPLATE" ]; then
    DEPLOY_ENV="$DEPLOY_ENV,WARDEN_MODEL_ARMOR_TEMPLATE=$MODEL_ARMOR_TEMPLATE,WARDEN_MODEL_ARMOR_LOCATION=$MODEL_ARMOR_LOCATION"
fi
gcloud run deploy "$SERVICE_NAME" \
    --image="gcr.io/$PROJECT_ID/$SERVICE_NAME:latest" \
    --platform="managed" \
    --region="$REGION" \
    --memory="1Gi" \
    --cpu="1" \
    --max-instances="1" \
    --service-account="$RUNTIME_SERVICE_ACCOUNT" \
    --set-env-vars="$DEPLOY_ENV" \
    --project="$PROJECT_ID"

# 4. Fetch Service URL and authorize Cloud Tasks to invoke the private worker.
SERVICE_URL=$(gcloud run services describe "$SERVICE_NAME" --platform=managed --region="$REGION" --format="value(status.url)" --project="$PROJECT_ID")

echo "--> [4/5] Connecting authenticated Cloud Tasks workflow resume..."
gcloud run services add-iam-policy-binding "$SERVICE_NAME" \
    --member="serviceAccount:$TASK_SERVICE_ACCOUNT" \
    --role="roles/run.invoker" \
    --region="$REGION" \
    --project="$PROJECT_ID" >/dev/null
gcloud iam service-accounts add-iam-policy-binding "$TASK_SERVICE_ACCOUNT" \
    --member="serviceAccount:service-$PROJECT_NUMBER@gcp-sa-cloudtasks.iam.gserviceaccount.com" \
    --role="roles/iam.serviceAccountTokenCreator" \
    --project="$PROJECT_ID" >/dev/null
gcloud run services update "$SERVICE_NAME" \
    --region="$REGION" \
    --update-env-vars="WARDEN_SERVICE_URL=$SERVICE_URL,WARDEN_TASK_QUEUE=$TASK_QUEUE,WARDEN_TASK_LOCATION=$REGION,WARDEN_TASK_SERVICE_ACCOUNT=$TASK_SERVICE_ACCOUNT" \
    --project="$PROJECT_ID" >/dev/null

echo "============================================================================"
echo " ✅ Deployment Complete!"
echo " 🌐 Web Dashboard:  $SERVICE_URL"
echo " 📜 OpenAPI Docs:   $SERVICE_URL/docs"
echo " 🛡️  Red-Team API:   $SERVICE_URL/redteam/run"
echo " ⚡ Async resumes:   Cloud Tasks queue '$TASK_QUEUE'"
echo " 🔐 Runtime identity: $RUNTIME_SERVICE_ACCOUNT"
echo " 🔎 Cloud Trace:      $ENABLE_CLOUD_TRACE"
if [ -n "$MODEL_ARMOR_TEMPLATE" ]; then
    echo " 🛡️  Model Armor:      template '$MODEL_ARMOR_TEMPLATE' in $MODEL_ARMOR_LOCATION"
fi
echo "============================================================================"
