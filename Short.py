import logging
import os
from logging.handlers import RotatingFileHandler
from urllib.parse import urljoin  # 新增导入
from flask import Flask, render_template, request, redirect, jsonify  # 添加 jsonify
from flask_sqlalchemy import SQLAlchemy
import atexit
from config import domain

ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

# 模数 M 为 62 的 6 次方，确保加密后字符串正好为6位（注意 M 较大，但原口令 < 1000000）
M = 62 ** 6  # 56,800,235,584

# 线性变换参数 (A, B)
# 为保证 A 在模 M 意义下可逆，需与 M 互质。731 为合适的选择（731 = 17 * 43）
A = 731
B = 12345

# 定义字符位置置换
# 加密时，新字符串的第 i 个字符取自原 6 位字符串的 perm[i] 位置
perm = [3, 5, 0, 1, 4, 2]
# 计算置换的逆序：若加密时 new[i] = s[perm[i]]，解密时恢复 s[j] = new[inverse_perm[j]]
# 手工计算得到 inverse_perm = [2, 3, 5, 0, 4, 1]
inverse_perm = [2, 3, 5, 0, 4, 1]

def modinv(a, m):
    """
    扩展欧几里得算法，计算 a 在模 m 下的乘法逆元
    返回 x，使得 (a * x) % m == 1
    """
    # 初始化
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        # 整数除法
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    # 保证 x1 为正
    if x1 < 0:
        x1 += m0
    return x1


def base62_encode(n, length=6):
    """
    将整数 n 转换为 62 进制字符串，结果长度不足时左侧补 '0'
    """
    if n < 0:
        raise ValueError("负数无法编码")
    res = []
    # 当 n 为 0 时，也要返回 '0'
    if n == 0:
        res.append(ALPHABET[0])
    while n > 0:
        n, remainder = divmod(n, 62)
        res.append(ALPHABET[remainder])
    res.reverse()
    # 左侧补 '0'（这里的 '0' 对应 ALPHABET[0]）
    s = ''.join(res)
    return s.rjust(length, ALPHABET[0])


def base62_decode(s):
    """
    将 62 进制字符串 s 转换回对应的整数
    """
    n = 0
    for ch in s:
        n = n * 62 + ALPHABET.index(ch)
    return n


def encrypt(plain):
    try:
        if not isinstance(plain, int) or not (0 <= plain < 1000000):
            raise ValueError("口令必须为 0 到 999999 的整数")

        # 线性变换
        y = (A * plain + B) % M
        base_str = base62_encode(y, length=6)

        encrypted_chars: list[str] = [''] * 6
        for i in range(6):
            if perm[i] >= len(base_str):
                raise IndexError(f"置换索引越界: perm[{i}] = {perm[i]}")
            encrypted_chars[i] = base_str[perm[i]]

        return ''.join(encrypted_chars)
    except Exception as e:
        logger.error(f"加密失败: {str(e)}", exc_info=True)
        raise RuntimeError("短链接生成失败") from e


# 配置日志
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# 创建一个 RotatingFileHandler，最多保留 3 个备份，每个日志文件最大 1MB
handler = RotatingFileHandler('decrypt.log', maxBytes=1024*1024, backupCount=3)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# 在应用退出时添加（可选）
atexit.register(lambda: handler.close())

def decrypt(encrypted):
    """
    解密函数：
    1. 对加密字符串应用逆位置置换，恢复加密前的 6 位 62 进制字符串
    2. 将 62 进制字符串转换为整数 y
    3. 使用逆线性变换计算出原始整数： plain = (inv_A * (y - B)) % M
    """
    try:
        if not isinstance(encrypted, str) or len(encrypted) != 6:
            raise ValueError("加密口令必须为6位字符串")

        logger.debug(f"开始解密加密字符串: {encrypted}")

        # 初始化为存储字符串的列表
        base_chars: list[str] = [''] * 6
        for j in range(6):
            base_chars[j] = encrypted[inverse_perm[j]]
        base_str = ''.join(base_chars)

        logger.debug(f"逆位置置换后的 62 进制字符串: {base_str}")

        # 62 进制字符串转换成整数 y
        y = base62_decode(base_str)

        logger.debug(f"转换后的整数 y: {y}")

        # 计算 A 在模 M 下的逆元
        inv_A = modinv(A, M)

        # 逆线性变换（注意 (y - B) 可能为负，因此先取模 M 再乘）
        plain = (inv_A * ((y - B) % M)) % M

        # 新增原始 ID 范围校验
        if not (0 <= plain < 1000000):
            logger.error(f"解密数值超出有效范围: {plain}")
            raise ValueError("无效的短链接")

        logger.debug(f"解密后的原始整数: {plain}")
        return plain
    except Exception as e:
        logger.error(f"解密过程中出现错误: {e}", exc_info=True)
        raise

short_url_flask_app = Flask(__name__)
# 使用环境变量管理密钥
short_url_flask_app.secret_key = os.environ.get('SECRET_KEY', 'short_url')

# 打印 short_url_flask_app 的类型
print(type(short_url_flask_app))

# 使用SQLAlchemy管理数据库连接
short_url_flask_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Clhkx_LongURL_2_ShortURL.db'
short_url_flask_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(short_url_flask_app)

# 定义模型类
class Urls(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    # 移除 short_url 列
    # 添加唯一约束
    long_url = db.Column(db.Text, nullable=False, unique=True)  # 修改行

with short_url_flask_app.app_context():
    db.create_all()

def create_short_url(long_url, custom_suffix=None):
    try:
        if custom_suffix:
            combined_url = urljoin(long_url.rstrip('/') + '/', custom_suffix.lstrip('/'))
        else:
            combined_url = long_url

        existing_link = Urls.query.filter_by(long_url=combined_url).first()
        if existing_link:
            return encrypt(existing_link.id), combined_url

        new_link = Urls(long_url=combined_url)
        db.session.add(new_link)
        db.session.flush()
        new_id = new_link.id
        db.session.commit()
        return encrypt(new_id), combined_url
    except Exception as e:
        db.session.rollback()
        logger.error(f"数据库操作失败: {str(e)}", exc_info=True)
        raise RuntimeError("短链接创建失败") from e



# 路由：主页，显示输入框
@short_url_flask_app.route("/", methods=["GET", "POST"])
@short_url_flask_app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        is_api = 'api' in request.args or 'api' in request.form  # 新增 API 参数检测
        long_url = request.form.get("long_url", "").strip()      # 改用 get 方法避免 KeyError
        custom_suffix = request.form.get("custom_suffix", "").strip()

        # 错误处理改为支持两种格式
        if not long_url:
            error_msg = "请输入一个有效的长链接！"
            return jsonify({"error": error_msg}), 400 if is_api else render_template("short.html", error=error_msg)

        if not long_url.startswith(('http://', 'https://')):
            error_msg = "请输入有效的 HTTP/HTTPS 链接"
            return jsonify({"error": error_msg}), 400 if is_api else render_template("short.html", error=error_msg)

        try:
            short_url, combined_url = create_short_url(long_url, custom_suffix)
        except Exception as e:
            logger.error(f"创建短链接失败: {str(e)}", exc_info=True)
            error_msg = "短链接生成失败，请重试"
            return jsonify({"error": error_msg}), 500 if is_api else render_template("short.html", error=error_msg)

        # 根据参数返回不同格式
        if is_api:
            return jsonify({
                "short_url": domain + short_url,
                "long_url": combined_url
            }), 201
        return render_template("short.html", short_url=short_url,domain=domain)

    return render_template("short.html")

# 路由：处理短链接访问
@short_url_flask_app.route("/<short_url>")
def redirect_to_long_url(short_url):
    try:
        original_id = decrypt(short_url)
        # 旧方式（已废弃）
        # link = Urls.query.get(original_id)
        # 新方式（使用 session.get()）
        link = db.session.get(Urls, original_id)
        if not link:
            raise ValueError("短链接不存在")
        return redirect(link.long_url)
    except ValueError as e:
        logger.warning(f"无效短链接请求: {short_url} - {str(e)}")
        return "Short URL not found!", 404
    except Exception as e:
        logger.error(f"重定向失败: {short_url} - {str(e)}", exc_info=True)
        return "服务器内部错误", 500

if __name__ == '__main__':
    # 启动 Flask 应用
    short_url_flask_app.run(debug=True, host='0.0.0.0', port=5000)
