# DDBMS_Project_Anand_Soura_Vineeta

File to run - n_1.py
Port - 5001

For multiple nodes - same file can be copied and run on different ports like 5002, 5003 and so on.
Required installations - MySQL on port 3306, DB - test, user - root, password - 1234

API curls -

->Horizontal node connection API - 

curl --location --request POST '127.0.0.1:5001/connect_node' \
--header 'Content-Type: application/json' \
--data-raw '{
    "nodes":["http://127.0.0.1:5002"]
}'

Vertical functional APIs -

->User creation -

curl --location --request GET '127.0.0.1:5001/add_user/control_centre' \
--data-raw ''

->Getting chain -

curl --location --request GET '127.0.0.1:5001/get_chain' \
--data-raw ''

->Adding transactions -

curl --location --request POST '127.0.0.1:5001/add_transaction' \
--header 'Content-Type: application/json' \
--data-raw '{
    "sender":"756e44a8a66a5e23d66ee74d3ae2da3ed03d2a8667566d54ed694cc4a604765b",
    "receiver": "22d63195b78ba153318745f2ea7ae8dbc5c59d7ddfaca90d8aba3ca8a546539b",
    "data": "{'Update':{'A':[3, 2, 3]},{'Delete':{'Index':1}}}",
    "amount": 100
}'

->Mining block -

curl --location --request GET '127.0.0.1:5001/mine_block/756e44a8a66a5e23d66ee74d3ae2da3ed03d2a8667566d54ed694cc4a604765b' \
--data-raw ''
