# Update api keys
sed -i -r 's/censys_api_id: ""/censys_api_id: \"'$CENSYS_API_ID'\"/g' ../api.yaml
sed -i -r 's/censys_secret: ""/censys_secret: \"'$CENSYS_SECRET'\"/g' ../api.yaml
sed -i -r 's/shodan: ""/shodan: \"'$SHODQN'\"/g' ../api.yaml
sed -i -r 's/huntio: ""/huntio: \"'$HUNTIO'\"/g' ../api.yaml

./NoWhere2Hide
