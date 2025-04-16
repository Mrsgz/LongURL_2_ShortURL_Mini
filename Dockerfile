# 基础镜像
FROM python:3.11-slim

# 设置工作目录
WORKDIR /app

# 拷贝依赖文件并安装
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 拷贝应用程序文件
COPY . .

# 暴露端口
EXPOSE 5000

# 启动应用
CMD ["python", "Short.py"]
