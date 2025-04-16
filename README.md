### 1、mod your domain

### 2、生成docker镜像
```
docker build -t short_app .
```
### 3、创建持久化文件
```
sqlite3 Clhkx_LongURL_2_ShortURL.db ""
touch decrypt.log
```
### 4、启动容器
```
docker run -d -p 5000:5000 -v ./decrypt.log:/app/decrypt.log -v ./Clhkx_LongURL_2_ShortURL.db:/app/Clhkx_LongURL_2_ShortURL.db short_app
```
