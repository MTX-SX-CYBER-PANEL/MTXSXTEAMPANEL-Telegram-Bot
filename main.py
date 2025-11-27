#بانل مقدم هديه من S1X     TEAM 
#البانل صناعه عمك مصري بي الكامل 
#╭───𓆩🛡️𓆪───╮
#      👨‍💻 𝘿𝙚𝙫: @UXD_0 
#      📢   𝘾𝙝: @UXD_0
#سنكر لا تسرق
#تمت برمجة البوت بالكامل By MTX 
#مش مسامح اي حد يخمط الملف بدون اذني
#سيب الحقوق بدل ما انيكك اقسم بي الله 
#حط توكن الضيف في سطر 180
import os
import json
import time
import requests
import telebot
import threading
from telebot import types
from byte import Encrypt_ID, encrypt_api

TOKEN = "8479232901:AAHISK024UXSqENcIy3_zR-__B5Romwp1BM"
bot = telebot.TeleBot(TOKEN)

users_file = "users.json"
developers_file = "developers.json"
groups_file = "groups.json"
JwT_tokw = None
TOKEN_REFRESH_INTERVAL = 3600  # One hour

# تهيئة الملفات
def initialize_files():
    if not os.path.exists(users_file):
        with open(users_file, "w") as f:
            json.dump({}, f)

    if not os.path.exists(developers_file):
        with open(developers_file, "w") as f:
            json.dump({"developers": [7260243555]}, f)

    if not os.path.exists(groups_file):
        with open(groups_file, "w") as f:
            json.dump({"allowed_chats": []}, f)

initialize_files()

# جلب المجموعات المصرح بها
def get_allowed_chats():
    try:
        with open(groups_file, "r") as f:
            data = json.load(f)
        return data.get("allowed_chats", [])
    except:
        return []

# حفظ المجموعات
def save_allowed_chats(chats):
    with open(groups_file, "w") as f:
        json.dump({"allowed_chats": chats}, f)

# التحقق إذا المجموعة مصرح بها
def is_allowed_chat(message):
    allowed_chats = get_allowed_chats()
    return message.chat.id in allowed_chats

# تفعيل البوت في المجموعة
@bot.message_handler(commands=['MTX'])
def set_group(message):
    # تحقق إن اللي بيستخدم الأمر مطور
    if not is_developer(message.from_user.id):
        bot.send_message(message.chat.id, "🚫 هذا الأمر للمطورين فقط.")
        return

    allowed_chats = get_allowed_chats()

    # إضافة الجروب
    if message.chat.id not in allowed_chats:
        allowed_chats.append(message.chat.id)
        save_allowed_chats(allowed_chats)
        bot.send_message(message.chat.id, f"✅ تم تفعيل البوت في هذه المجموعة.\n🆔 {message.chat.id}")
    else:
        bot.send_message(message.chat.id, "ℹ️ هذه المجموعة مفعّلة بالفعل.")


# ⛔ أمر /kill لإلغاء التفعيل
@bot.message_handler(commands=['kill'])
def kill_group(message):
    # تحقق إن اللي بيستخدم الأمر مطور
    if not is_developer(message.from_user.id):
        bot.send_message(message.chat.id, "🚫 هذا الأمر للمطورين فقط.")
        return

    allowed_chats = get_allowed_chats()

    # حذف الجروب
    if message.chat.id in allowed_chats:
        allowed_chats.remove(message.chat.id)
        save_allowed_chats(allowed_chats)
        bot.send_message(message.chat.id, "❌ تم إلغاء تفعيل البوت في هذه المجموعة.")
    else:
        bot.send_message(message.chat.id, "ℹ️ هذه المجموعة غير مفعّلة أساسًا.")

import threading
import requests
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

JwT_tokw = None
TOKEN_REFRESH_INTERVAL = 300  # 5 دقايق – عدلها براحتك


# ----------------------------- #
#        تشفير الـ API          #
# ----------------------------- #

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()


# ----------------------------- #
#       صانع التوكن الأصلي       #
# ----------------------------- #

def TOKEN_MAKER(OLD_ACCESS_TOKEN, NEW_ACCESS_TOKEN, OLD_OPEN_ID, NEW_OPEN_ID, uid):
    now = datetime.now()
    now = str(now)[:len(str(now)) - 7]

    data = bytes.fromhex(
        '1a13323032352d30372d33302031313a30323a3531220966726565206669726528013a07312e3131342e32422c416e64726f6964204f5320372e312e32202f204150492d323320284e32473438482f373030323530323234294a0848616e6468656c645207416e64726f69645a045749464960c00c68840772033332307a1f41524d7637205646507633204e454f4e20564d48207c2032343635207c203480019a1b8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e319a012b476f6f676c657c31663361643662372d636562342d343934622d383730622d623164616364373230393131a2010c3139372e312e31322e313335aa0102656eb201203939366136323964626364623339363462653662363937386635643831346462ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d473935354eea014066663930633037656239383135616633306134336234613966363031393531366530653463373033623434303932353136643064656661346365663531663261f00101ca0207416e64726f6964d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003daa907e803899b07f003bf0ff803ae088004999b078804daa9079004999b079804daa907c80403d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138363933a80503b205094f70656e474c455332b805ff7fc00504e005dac901ea0507616e64726f6964f2055c4b71734854394748625876574c6668437950416c52526873626d43676542557562555551317375746d525536634e30524f3751453141486e496474385963784d614c575437636d4851322b7374745279377830663935542b6456593d8806019006019a060134a2060134b2061e40001147550d0c074f530b4d5c584d57416657545a065f2a091d6a0d5033'
        # (هنا يبقى نفس hex الطويل اللي عندك — انسخه كامل كما هو)
    )

    data = data.replace(OLD_OPEN_ID.encode(), NEW_OPEN_ID.encode())
    data = data.replace(OLD_ACCESS_TOKEN.encode(), NEW_ACCESS_TOKEN.encode())

    encrypted = encrypt_api(data.hex())
    Final_Payload = bytes.fromhex(encrypted)

    headers = {
        'X-Unity-Version': '2018.4.11f1',
        'ReleaseVersion': 'ob51',
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-GA': 'v1 1',
        'Authorization': 'Bearer ...',   # نفس اللي عندك
        'Content-Length': '928',
        'User-Agent': 'Dalvik/2.1.0',
        'Host': 'loginbp.common.ggbluefox.com',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip'
    }

    url = "https://loginbp.common.ggbluefox.com/MajorLogin"
    response = requests.post(url, headers=headers, data=Final_Payload, verify=False)

    if response.status_code == 200:
        if len(response.text) < 10:
            return False

        base = response.text[
            response.text.find("eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ"):
            -1
        ]

        second_dot = base.find(".", base.find(".") + 1)
        base = base[:second_dot + 44]
        return base


# ----------------------------- #
#  جلب التوكن تلقائيًا بدون API #
# ----------------------------- #

def fetch_token():
    global JwT_tokw

    try:
        uid = "4160614447"
        password = "7A1B7A846795CA7EB610920D26B9D7EC446811C8A8161E29D34C7C4B5C45507D"

        # المرحلة 1: طلب guest token من جارينا
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {
            "Host": "100067.connect.garena.com",
            "User-Agent": "GarenaMSDK/4.0.19P4",
            "Content-Type": "application/x-www-form-urlencoded"
        }

        data = {
            "uid": uid,
            "password": password,
            "response_type": "token",
            "client_type": "2",
            "client_id": "100067",
            "client_secret": ""
        }

        r = requests.post(url, headers=headers, data=data)
        d = r.json()

        NEW_ACCESS_TOKEN = d["access_token"]
        NEW_OPEN_ID = d["open_id"]

        OLD_ACCESS_TOKEN = "ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a"
        OLD_OPEN_ID = "996a629dbcdb3964be6b6978f5d814db"

        token = TOKEN_MAKER(
            OLD_ACCESS_TOKEN,
            NEW_ACCESS_TOKEN,
            OLD_OPEN_ID,
            NEW_OPEN_ID,
            uid
        )

        if token:
            JwT_tokw = token
            print("[TOKEN] Updated:", token[:50], "...")
        else:
            print("TOKEN MAKER FAILED")

    except Exception as e:
        print("Error:", e)

    threading.Timer(TOKEN_REFRESH_INTERVAL, fetch_token).start()
    return True


# ----------------------------- #
#        تشغيل التحديث          #
# ----------------------------- #

fetch_token()

# التحقق إذا المستخدم مطور
def is_developer(user_id):
    try:
        with open(developers_file, "r") as f:
            data = json.load(f)
        return user_id in data.get("developers", [])
    except:
        return False

# إرسال طلب إضافة صديق
def request_add_friend(player_id):
    if not JwT_tokw:
        if not fetch_token():
            return "🚫 Token not currently available, please try again later."

    try:
        encrypted_id = Encrypt_ID(player_id)
        payload = f"08a7c4839f1e10{encrypted_id}1801"
        payload_bytes = bytes.fromhex(encrypt_api(payload))

        url = "https://clientbp.ggblueshark.com/RequestAddingFriend"
        headers = {
            "Authorization": f"Bearer {JwT_tokw}",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB51",
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(payload_bytes)),
            "User-Agent": "Dalvik/2.1.0 (Linux; Android 9)",
            "Connection": "close",
        }
        
        response = requests.post(url, headers=headers, data=payload_bytes)
        if response.status_code == 200:
            return "✅ تمت الإضافة"
        return f"API Error: {response.status_code}"
    except Exception as e:
        return f"Request Error: {str(e)}"

# حذف صديق
def remove_friend(player_id):
    if not JwT_tokw:
        if not fetch_token():
            return "🚫 Token not currently available, please try again later."
    try:
        encrypted_id = Encrypt_ID(player_id)
        payload = f"08a7c4839f1e10{encrypted_id}1801"
        payload_bytes = bytes.fromhex(encrypt_api(payload))

        url = "https://clientbp.ggblueshark.com/RemoveFriend"
        headers = {
            "Authorization": f"Bearer {JwT_tokw}",  
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB51",
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(payload_bytes)),
            "User-Agent": "Dalvik/2.1.0 (Linux; Android 9)",
            "Connection": "close",
        }
        
        response = requests.post(url, headers=headers, data=payload_bytes)
        if response.status_code == 200:
            return True
        return f"API Error: {response.status_code}"
    except Exception as e:
        return f"Request Error: {str(e)}"

# حفظ المستخدم
def save_user(user_id, uid, days):
    try:
        with open(users_file, "r") as f:
            users = json.load(f)
    except:
        users = {}
    
    expiry = int(time.time()) + (int(days) * 86400)
    users.setdefault(str(user_id), {})
    users[str(user_id)][uid] = {"expiry": expiry}
    
    with open(users_file, "w") as f:
        json.dump(users, f)

# جلب أصدقاء المستخدم
def get_user_friends(user_id):
    try:
        with open(users_file, "r") as f:
            users = json.load(f)
        return users.get(str(user_id), {})
    except:
        return {}

# صيغة الوقت المتبقي
def format_remaining_time(expiry_time):
    remaining_seconds = int(expiry_time - time.time())
    if remaining_seconds <= 0:
        return "⛔ انتهت الصلاحية"
    days = remaining_seconds // 86400
    hours = (remaining_seconds % 86400) // 3600
    minutes = (remaining_seconds % 3600) // 60
    return f"📅 {days} يوم و {hours} ساعة و {minutes} دقيقة"

# التحقق التلقائي من انتهاء الوقت
def auto_check_expiry():
    try:
        with open(users_file, "r") as f:
            users = json.load(f)
            
        modified = False
        current_time = time.time()
        
        for user_id in list(users.keys()):
            for uid in list(users[user_id].keys()):
                expiry = users[user_id][uid]["expiry"]
                if expiry < current_time:
                    remove_friend(uid)
                    del users[user_id][uid]
                    modified = True
                    print(f"[🗑️] Removed expired UID {uid} from user {user_id}")
            
            if not users[user_id]:
                del users[user_id]
                modified = True
                
        if modified:
            with open(users_file, "w") as f:
                json.dump(users, f)
                
    except Exception as e:
        print(f"[⚠️] Error in auto_check_expiry: {e}")
    finally:
        threading.Timer(3600, auto_check_expiry).start()

# أوامر البوت
@bot.message_handler(commands=['help'])
def help_command(message):
    if not is_allowed_chat(message):
        bot.reply_to(message, "⚠️ هذا البوت يعمل فقط في المجموعات المصرح بها!")
        return
    help_text = f"""
━━━━━━━━━━━━━━━━━━━━
<b>✨🚀 〔 MTX BOT SX  〕🚀✨</b>
━━━━━━━━━━━━━━━━━━━━
<i>💎 لوحة تحكم احترافية لإدارة الأصدقاء 💎</i>

<b>🧩 الأوامر:</b>

<code>/bot [ID]</code>
<i>➕ إضافة صديق لمدة يوم واحد.</i>

<code>/remove [ID]</code>
<i>➖ حذف صديق معين عبر المعرف.</i>

<code>/MTX</code>
<i>⚙️ تفعيل البوت في المجموعة (للمطورين فقط).</i>

━━━━━━━━━━━━━━━━━━━━
<b>👤 معرفك:</b> <code>{message.from_user.id}</code>
<b>👨‍💻 المطور:</b> @noseyrobot
<b>💬 المجموعة:</b> https://t.me/T_z_X_team
━━━━━━━━━━━━━━━━━━━━
"""
    bot.send_message(message.chat.id, help_text, parse_mode="HTML")

@bot.message_handler(commands=['bot'])
def add_user(message):
    if not is_allowed_chat(message):
        return
    try:
        _, user_id = message.text.split()
        response = request_add_friend(user_id)
        if "✅" in response:
            save_user(message.from_user.id, user_id, 1)
            bot.reply_to(message, f"✅ تمت إضافة {user_id} لمدة يوم 1")
        else:
            bot.reply_to(message, f"⚠️ لم يتم الإضافة.\n📩 {response}")
    except:
        bot.reply_to(message, "❌ الاستخدام:\n/bot <id>")

@bot.message_handler(commands=['remove'])
def remove_user_cmd(message):
    if not is_allowed_chat(message):
        return
    try:
        _, user_id = message.text.split()
        if remove_friend(user_id):
            bot.reply_to(message, f"✅ تم حذف {user_id}")
        else:
            bot.reply_to(message, "❌ اللاعب غير موجود أو حدث خطأ.")
    except:
        bot.reply_to(message, "❌ الاستخدام:\n/remove <id>")

@bot.message_handler(commands=['list'])
def list_users(message):
    if not is_allowed_chat(message):
        return
    friends = get_user_friends(message.from_user.id)
    if not friends:
        bot.reply_to(message, "📜 لا يوجد لاعبون حالياً.")
        return
    reply_text = "📋 قائمة اللاعبين:\n"
    for uid, info in friends.items():
        remaining = format_remaining_time(info.get("expiry", 0))
        reply_text += f"\n🆔 {uid}\n⏳ {remaining}\n"
    bot.reply_to(message, reply_text)

if __name__ == "__main__":
    fetch_token()
    auto_check_expiry()
    bot.polling(none_stop=True)