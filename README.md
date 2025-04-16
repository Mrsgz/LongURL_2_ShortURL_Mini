## USER

### 1、modify your domain in config.py
### 2、make docker image
```
docker build -t short_app .
```
### 3、creat files
```
sqlite3 Clhkx_LongURL_2_ShortURL.db ""
touch decrypt.log
```
### 4、start docker
```
docker run -d -p 5000:5000 -v ./decrypt.log:/app/decrypt.log -v ./Clhkx_LongURL_2_ShortURL.db:/app/Clhkx_LongURL_2_ShortURL.db short_app
```