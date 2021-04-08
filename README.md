Build and install drogon (forked to allow passing the model class to the controller as a template argument):
```bash
git clone https://github.com/xD8A/drogon
cd drogon
git submodule update --init
mkdir build
cd build
cmake ..
make && sudo make install
```

Create the project and setup it (./{config.json,main.cc}):
```bash
drogon_ctl create project drogon-chat-api && cd ./drogon-chat-api
echo 'configure_file(config.json config.json COPYONLY)' >> CMakeLists.txt
```

Create tables (./schema.sql) and customize models (./models/model.json):
```bash
sqlite3 app.db < schema.sql
drogon_ctl create model ./models/
echo 'configure_file(app.db app.db COPYONLY)'>> CMakeLists.txt
```

Install dependencies
```bash
mkdir libs && (cd ./libs \
  && git submodule add https://github.com/trusch/libbcrypt.git \
  && git submodule add https://github.com/Thalhammer/jwt-cpp.git)
cat << 'EOF' >> CMakeLists.txt

add_subdirectory(libs/libbcrypt)
target_link_libraries(${PROJECT_NAME} PRIVATE bcrypt)
target_include_directories(${PROJECT_NAME}
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/libs/libbcrypt/include) 
EOF
cat << 'EOF' >> CMakeLists.txt

add_subdirectory(libs/jwt-cpp)
target_link_libraries(${PROJECT_NAME} PRIVATE jwt-cpp)
target_include_directories(${PROJECT_NAME}
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/libs/jwt-cpp/include)
EOF
```

Create filter
```bash
(cd ./filters && drogon_ctl create filter LoginFilter)
```

Custom:
* models (see ./models/UsersExt.{h,cc});
* filters (see ./filters/LoginFilter.{h,cc});
* controllers (see ./controllers/UsersCtrl.{h,cc}).

Create admin user:
```bash
sqlite3 app.db \
"INSERT INTO users (name, email, password_hash)"\
" VALUES ('admin', 'admin@example.com', '"\
`python3 -c 'import bcrypt;print(bcrypt.hashpw(b"password", bcrypt.gensalt()).decode())'`\
"');"
```

Build and run.

Fail (401):
```bash
curl -i -H "Content-Type: application/json" http://localhost:8080/users
```

Success: 
```bash
JWT_TOKEN=`curl -s -H "Content-Type: application/json" \
  -X POST \
  -d '{"name":"admin","password":"password"}' \
  http://localhost:8080/login \
| python3 -c "import sys, json; print(json.load(sys.stdin)['token'])"` \
&& curl -i -H "Content-Type: application/json" -H "Authorization: Bearer$JWT_TOKEN" \
  http://localhost:8080/users
```
