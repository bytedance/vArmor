#!/bin/bash
SOURCE_REGION=ap-southeast-1
TARGET_REGION=cn-beijing
NAMESPACE=varmor-test
VERSION=""

usage() {
    echo "Usage: sync-artifacts.sh --version VERSION [options]

Settings:
    -v, --version VERSION: The version is the image tag, also the chart version in the repo.

Options:
    -s, --source_region REGION: The source region of the repo where you want to sync from. Default: ap-southeast-1
    -t, --target_region REGION: The target region of the repo where you want to sync to. Default: cn-beijing
    -n, --namespace NAMESPACE: The namespace where the artifacts are located in the repo. Default: varmor-test
    -p, --pull: Whether to pull artifacts from the source repo or just use the local artifacts. Default: false
    -c, --clean: Clean the local artifacts."
}

clean() {
    for image_id in $(docker images | grep $NAMESPACE | awk '{print $3}')
    do
        echo "[+] Delete $image_id"
        docker rmi -f $image_id;
    done
}

### main
pull=0
while [[ "$1" =~ ^- && ! "$1" == "--" ]]; do
    case "$1" in
        -s | --source_region )
            SOURCE_REGION=$2
            shift
            ;;
        -t | --target_region )
            TARGET_REGION=$2
            shift
            ;;
        -n | --namespace )
            NAMESPACE=$2
            shift
            ;;
        -v | --version )
            VERSION=$2
            shift
            ;;
        -p | --pull )
            pull=1
            ;;
        -c | --clean )
            clean
            exit 0
            ;;
        -h | --help )
            usage
            exit 0
    esac
    shift
done

if [[ -z $VERSION ]]; then
    usage
    exit 1
fi

echo "[+] Please confirm the configurations:
* Source Region: $SOURCE_REGION 
* Target Region: $TARGET_REGION
* Namespace: $NAMESPACE
* Version: $VERSION
* Pull artifacts from the source repo: $pull"

echo ""
read -p "[+] Continue (y/n)? " choice
echo ""
case "$choice" in 
  y|Y ) echo "[+] Start sync...";;
  n|N ) exit 1;;
  * ) exit 1;;
esac

SOURCE_DOMAIN="elkeid-$SOURCE_REGION.cr.volces.com"
TARGET_DOMAIN="elkeid-$TARGET_REGION.cr.volces.com"

if [[ $pull == 1 ]]; then
    docker pull $SOURCE_DOMAIN/$NAMESPACE/varmor:$VERSION-arm64
    if [ $? -ne 0 ]; then
        exit 1
    fi

    docker pull $SOURCE_DOMAIN/$NAMESPACE/varmor:$VERSION-amd64
    if [ $? -ne 0 ]; then
        exit 1
    fi

    docker pull $SOURCE_DOMAIN/$NAMESPACE/classifier:$VERSION-arm64
    if [ $? -ne 0 ]; then
        exit 1
    fi

    docker pull $SOURCE_DOMAIN/$NAMESPACE/classifier:$VERSION-amd64
    if [ $? -ne 0 ]; then
        exit 1
    fi

    helm pull oci://$SOURCE_DOMAIN/$NAMESPACE/varmor --version ${VERSION#v}
    if [ $? -ne 0 ]; then
        exit 1
    fi
fi

echo "[+] Push varmor image"
docker tag $SOURCE_DOMAIN/$NAMESPACE/varmor:$VERSION-arm64 $TARGET_DOMAIN/$NAMESPACE/varmor:$VERSION-arm64
docker push $TARGET_DOMAIN/$NAMESPACE/varmor:$VERSION-arm64
if [ $? -ne 0 ]; then
    exit 1
fi
echo ""
docker tag $SOURCE_DOMAIN/$NAMESPACE/varmor:$VERSION-amd64 $TARGET_DOMAIN/$NAMESPACE/varmor:$VERSION-amd64
docker push $TARGET_DOMAIN/$NAMESPACE/varmor:$VERSION-amd64
echo ""

docker manifest rm $TARGET_DOMAIN/$NAMESPACE/varmor:$VERSION
docker manifest create $TARGET_DOMAIN/$NAMESPACE/varmor:$VERSION $TARGET_DOMAIN/$NAMESPACE/varmor:$VERSION-arm64 $TARGET_DOMAIN/$NAMESPACE/varmor:$VERSION-amd64
docker manifest push $TARGET_DOMAIN/$NAMESPACE/varmor:$VERSION
echo ""

echo "[+] Push classifier image"
docker tag $SOURCE_DOMAIN/$NAMESPACE/classifier:$VERSION-arm64 $TARGET_DOMAIN/$NAMESPACE/classifier:$VERSION-arm64
docker push $TARGET_DOMAIN/$NAMESPACE/classifier:$VERSION-arm64
if [ $? -ne 0 ]; then
    exit 1
fi
echo ""
docker tag $SOURCE_DOMAIN/$NAMESPACE/classifier:$VERSION-amd64 $TARGET_DOMAIN/$NAMESPACE/classifier:$VERSION-amd64
docker push $TARGET_DOMAIN/$NAMESPACE/classifier:$VERSION-amd64
echo ""
docker manifest rm $TARGET_DOMAIN/$NAMESPACE/classifier:$VERSION
docker manifest create $TARGET_DOMAIN/$NAMESPACE/classifier:$VERSION $TARGET_DOMAIN/$NAMESPACE/classifier:$VERSION-arm64 $TARGET_DOMAIN/$NAMESPACE/classifier:$VERSION-amd64
docker manifest push $TARGET_DOMAIN/$NAMESPACE/classifier:$VERSION
echo ""

echo "[+] Push chart"
helm push varmor-${VERSION#v}.tgz oci://$TARGET_DOMAIN/$NAMESPACE
