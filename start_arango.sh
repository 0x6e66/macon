#!/bin/bash

arangodb_container_id=$(docker ps -q -a -f name=arangodb-instance)

arango_auth="ARANGO_NO_AUTH=1"

if [ -z $arangodb_container_id ]; then
    
    if [[ $arango_auth == "ARANGO_NO_AUTH=1" ]]; then
        echo "WARNING: The arangodb instance is created without authentication"
        echo "  Don't use this setting in production."
        echo "  See other authentication methods here: https://hub.docker.com/_/arangodb#choosing-an-authentication-method"
        echo ""
    fi

    docker run -d -p 8529:8529 -e $arango_auth --name arangodb-instance arangodb
else
    docker start $arangodb_container_id
fi
