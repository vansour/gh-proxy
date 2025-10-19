#!/bin/bash
# Multi-architecture Docker build script
# Builds and optionally pushes images for linux/amd64 and linux/arm64

set -e

# Configuration
IMAGE_NAME="${1:-gh-proxy:latest}"
PLATFORMS="${2:-linux/amd64,linux/arm64}"
PUSH="${3:-false}"
BUILDKIT_PROGRESS="${4:-auto}"

echo "=================================================="
echo "Multi-Architecture Docker Build"
echo "=================================================="
echo "Image: $IMAGE_NAME"
echo "Platforms: $PLATFORMS"
echo "Push: $PUSH"
echo "BuildKit Progress: $BUILDKIT_PROGRESS"
echo "=================================================="

# Check if buildx is available
if ! docker buildx version > /dev/null 2>&1; then
    echo "ERROR: Docker buildx is not installed or not available"
    echo "Install it with: docker run --rm --privileged docker/binfmt:latest --install all"
    exit 1
fi

# Build command
BUILD_CMD="docker buildx build"
BUILD_CMD="$BUILD_CMD --platform $PLATFORMS"
BUILD_CMD="$BUILD_CMD --progress=$BUILDKIT_PROGRESS"
BUILD_CMD="$BUILD_CMD -t $IMAGE_NAME"

# Add push flag if specified
if [ "$PUSH" = "true" ]; then
    BUILD_CMD="$BUILD_CMD --push"
    echo "Building and pushing image..."
else
    BUILD_CMD="$BUILD_CMD --output type=docker"
    echo "Building image locally..."
fi

# Add build arguments for optimization
BUILD_CMD="$BUILD_CMD --build-arg RUST_VERSION=1.75"
BUILD_CMD="$BUILD_CMD ."

# Execute build
echo "Command: $BUILD_CMD"
echo "=================================================="
eval "$BUILD_CMD"

echo "=================================================="
echo "Build completed successfully!"
echo "=================================================="

if [ "$PUSH" != "true" ]; then
    echo ""
    echo "To push the image, run:"
    echo "  docker buildx build --platform $PLATFORMS -t $IMAGE_NAME --push ."
fi
