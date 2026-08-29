#!/usr/bin/env bash
# ==============================================================================
# Warden: Automated Google Cloud Run & Firestore Deployment Script
# ==============================================================================
set -euo pipefail

PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-$(gcloud config get-value project 2>/dev/null || true)}"
REGION="${GOOGLE_CLOUD_REGION:-us-central1}"
SERVICE_NAME="warden-control-plane"
IMAGE_REPOSITORY="${WARDEN_IMAGE_REPOSITORY:-warden}"
IMAGE_URI="$REGION-docker.pkg.dev/$PROJECT_ID/$IMAGE_REPOSITORY/$SERVICE_NAME:latest"
WARDEN_RUNTIME_MODE="${WARDEN_MODE:-mock}"
TASK_QUEUE="${WARDEN_TASK_QUEUE:-warden-resume}"
ENABLE_CLOUD_TRACE="${WARDEN_ENABLE_CLOUD_TRACE:-true}"
MODEL_ARMOR_TEMPLATE="${WARDEN_MODEL_ARMOR_TEMPLATE:-}"
MODEL_ARMOR_LOCATION="${WARDEN_MODEL_ARMOR_LOCATION:-$REGION}"
WARDEN_MODEL="${WARDEN_MODEL:-gemini-3.5-flash}"
ENABLE_LIVE_GPU="${WARDEN_DEMO_LIVE_VM:-false}"
LIVE_GPU_ZONE="${WARDEN_LIVE_VM_ZONE:-us-central1-a}"
LIVE_GPU_CONFIRM_PROJECT="${WARDEN_LIVE_VM_CONFIRM_PROJECT:-}"
ROLE_BINDINGS="${WARDEN_ROLE_BINDINGS:-}"
GENAI_LOCATION="${GOOGLE_CLOUD_LOCATION:-global}"
CLOUD_BUILD_SERVICE_ACCOUNT="${WARDEN_CLOUD_BUILD_SERVICE_ACCOUNT:-}"
SKIP_BUILD="${WARDEN_SKIP_BUILD:-false}"
ENABLE_CLOUD_EVIDENCE="${WARDEN_ENABLE_CLOUD_EVIDENCE:-true}"
EVIDENCE_BUCKET="${WARDEN_EVIDENCE_BUCKET:-}"
BILLING_EXPORT_TABLE="${WARDEN_BILLING_EXPORT_TABLE:-}"
CLOUD_SCOPE="${WARDEN_CLOUD_SCOPE:-projects/$PROJECT_ID}"
EVIDENCE_REQUIRE_LOCK="${WARDEN_EVIDENCE_REQUIRE_LOCK:-true}"

if [ -z "$PROJECT_ID" ]; then
    echo "Error: GOOGLE_CLOUD_PROJECT is not set and no default gcloud project found."
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
echo "Deploying Warden Operator Control Plane to Google Cloud Run"
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
    aiplatform.googleapis.com \
    modelarmor.googleapis.com \
    iamcredentials.googleapis.com \
    cloudasset.googleapis.com \
    securitycenter.googleapis.com \
    bigquery.googleapis.com \
    storage.googleapis.com \
    compute.googleapis.com \
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
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:$RUNTIME_SERVICE_ACCOUNT" \
    --role="roles/aiplatform.user" \
    --condition=None >/dev/null
if [ "$ENABLE_LIVE_GPU" = "true" ]; then
    if [ "$LIVE_GPU_CONFIRM_PROJECT" != "$PROJECT_ID" ]; then
        echo "Error: WARDEN_LIVE_VM_CONFIRM_PROJECT must exactly match $PROJECT_ID."
        exit 1
    fi
    echo "--> Enabling the bounded live NVIDIA L4 provider for Cloud Run..."
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:$RUNTIME_SERVICE_ACCOUNT" \
        --role="roles/compute.instanceAdmin.v1" \
        --condition=None >/dev/null
fi
if [ -n "$MODEL_ARMOR_TEMPLATE" ]; then
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:$RUNTIME_SERVICE_ACCOUNT" \
        --role="roles/modelarmor.user" \
        --condition=None >/dev/null
fi
if [ "$ENABLE_CLOUD_EVIDENCE" = "true" ]; then
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:$RUNTIME_SERVICE_ACCOUNT" \
        --role="roles/cloudasset.viewer" \
        --condition=None >/dev/null
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:$RUNTIME_SERVICE_ACCOUNT" \
        --role="roles/securitycenter.findingsViewer" \
        --condition=None >/dev/null
    if [ -n "$BILLING_EXPORT_TABLE" ]; then
        gcloud projects add-iam-policy-binding "$PROJECT_ID" \
            --member="serviceAccount:$RUNTIME_SERVICE_ACCOUNT" \
            --role="roles/bigquery.jobUser" \
            --condition=None >/dev/null
    fi
    if [ -n "$EVIDENCE_BUCKET" ]; then
        if [ "$EVIDENCE_REQUIRE_LOCK" = "true" ]; then
            RETENTION_LOCKED="$(gcloud storage buckets describe "gs://$EVIDENCE_BUCKET" --format='value(retentionPolicy.isLocked)' 2>/dev/null || true)"
            if [ "$RETENTION_LOCKED" != "True" ] && [ "$RETENTION_LOCKED" != "true" ]; then
                echo "Error: evidence bucket gs://$EVIDENCE_BUCKET does not have a locked retention policy."
                echo "Bucket Lock is irreversible; configure and lock it explicitly before deploying."
                exit 1
            fi
        fi
        gcloud storage buckets add-iam-policy-binding "gs://$EVIDENCE_BUCKET" \
            --member="serviceAccount:$RUNTIME_SERVICE_ACCOUNT" \
            --role="roles/storage.objectCreator" >/dev/null
        gcloud storage buckets add-iam-policy-binding "gs://$EVIDENCE_BUCKET" \
            --member="serviceAccount:$RUNTIME_SERVICE_ACCOUNT" \
            --role="roles/storage.legacyBucketReader" >/dev/null
    fi
fi

# 2. Build Container using Cloud Build
echo "--> [2/5] Preparing container image..."
gcloud artifacts repositories describe "$IMAGE_REPOSITORY" \
    --location="$REGION" \
    --project="$PROJECT_ID" >/dev/null 2>&1 || \
gcloud artifacts repositories create "$IMAGE_REPOSITORY" \
    --repository-format=docker \
    --location="$REGION" \
    --description="Warden control-plane container images" \
    --project="$PROJECT_ID"
BUILD_ARGS=(
    builds submit
    --tag "$IMAGE_URI"
    --project="$PROJECT_ID"
)
if [ "$SKIP_BUILD" = "true" ]; then
    echo "    Reusing existing image: $IMAGE_URI"
else
    echo "    Building with Google Cloud Build..."
    if [ -n "$CLOUD_BUILD_SERVICE_ACCOUNT" ]; then
        BUILD_ARGS+=(
            --service-account="$CLOUD_BUILD_SERVICE_ACCOUNT"
            --default-buckets-behavior=regional-user-owned-bucket
        )
    fi
    gcloud "${BUILD_ARGS[@]}"
fi

# 3. Deploy to Cloud Run
echo "--> [3/5] Deploying service to Google Cloud Run..."
DEPLOY_ENV="WARDEN_MODE=$WARDEN_RUNTIME_MODE,GOOGLE_CLOUD_PROJECT=$PROJECT_ID,GOOGLE_GENAI_USE_VERTEXAI=true,GOOGLE_CLOUD_LOCATION=$GENAI_LOCATION,WARDEN_ENABLE_CLOUD_TRACE=$ENABLE_CLOUD_TRACE,WARDEN_MODEL=$WARDEN_MODEL"
if [ "$ENABLE_LIVE_GPU" = "true" ]; then
    DEPLOY_ENV="$DEPLOY_ENV,WARDEN_DEMO_LIVE_VM=true,WARDEN_LIVE_VM_ZONE=$LIVE_GPU_ZONE,WARDEN_LIVE_VM_CONFIRM_PROJECT=$LIVE_GPU_CONFIRM_PROJECT"
fi
if [ -n "$MODEL_ARMOR_TEMPLATE" ]; then
    DEPLOY_ENV="$DEPLOY_ENV,WARDEN_MODEL_ARMOR_TEMPLATE=$MODEL_ARMOR_TEMPLATE,WARDEN_MODEL_ARMOR_LOCATION=$MODEL_ARMOR_LOCATION"
fi
if [ "$ENABLE_CLOUD_EVIDENCE" = "true" ]; then
    DEPLOY_ENV="$DEPLOY_ENV,WARDEN_CLOUD_SCOPE=$CLOUD_SCOPE,WARDEN_EVIDENCE_REQUIRE_LOCK=$EVIDENCE_REQUIRE_LOCK"
    if [ -n "$EVIDENCE_BUCKET" ]; then
        DEPLOY_ENV="$DEPLOY_ENV,WARDEN_EVIDENCE_BUCKET=$EVIDENCE_BUCKET"
    fi
    if [ -n "$BILLING_EXPORT_TABLE" ]; then
        DEPLOY_ENV="$DEPLOY_ENV,WARDEN_BILLING_EXPORT_TABLE=$BILLING_EXPORT_TABLE"
    fi
fi
gcloud run deploy "$SERVICE_NAME" \
    --image="$IMAGE_URI" \
    --platform="managed" \
    --region="$REGION" \
    --memory="1Gi" \
    --cpu="1" \
    --max-instances="1" \
    --timeout="600" \
    --service-account="$RUNTIME_SERVICE_ACCOUNT" \
    --no-allow-unauthenticated \
    --set-env-vars="$DEPLOY_ENV" \
    --project="$PROJECT_ID"

if [ -n "$ROLE_BINDINGS" ]; then
    # JSON contains commas, so use a delimiter that cannot occur in the map.
    gcloud run services update "$SERVICE_NAME" \
        --region="$REGION" \
        --update-env-vars="^|^WARDEN_ROLE_BINDINGS=$ROLE_BINDINGS" \
        --project="$PROJECT_ID" >/dev/null
fi

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
gcloud iam service-accounts add-iam-policy-binding "$TASK_SERVICE_ACCOUNT" \
    --member="serviceAccount:$RUNTIME_SERVICE_ACCOUNT" \
    --role="roles/iam.serviceAccountUser" \
    --project="$PROJECT_ID" >/dev/null
gcloud run services update "$SERVICE_NAME" \
    --region="$REGION" \
    --update-env-vars="WARDEN_SERVICE_URL=$SERVICE_URL,WARDEN_TASK_QUEUE=$TASK_QUEUE,WARDEN_TASK_LOCATION=$REGION,WARDEN_TASK_SERVICE_ACCOUNT=$TASK_SERVICE_ACCOUNT" \
    --project="$PROJECT_ID" >/dev/null

echo "============================================================================"
echo "Deployment complete"
echo "Web dashboard:     $SERVICE_URL"
echo "OpenAPI docs:      $SERVICE_URL/docs"
echo "Red-team API:      $SERVICE_URL/redteam/run"
echo "Async resumes:     Cloud Tasks queue '$TASK_QUEUE'"
echo "Runtime identity:  $RUNTIME_SERVICE_ACCOUNT"
echo "Cloud Trace:       $ENABLE_CLOUD_TRACE"
echo "Cloud evidence:    $ENABLE_CLOUD_EVIDENCE"
echo "Live GPU proof:     $ENABLE_LIVE_GPU"
if [ -n "$EVIDENCE_BUCKET" ]; then
    echo "Evidence archive:  gs://$EVIDENCE_BUCKET (lock required: $EVIDENCE_REQUIRE_LOCK)"
fi
if [ -n "$MODEL_ARMOR_TEMPLATE" ]; then
    echo "Model Armor:       template '$MODEL_ARMOR_TEMPLATE' in $MODEL_ARMOR_LOCATION"
fi
echo "============================================================================"
