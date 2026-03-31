import os
import logging
import requests
import json
import time
import re
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from aiogram import Bot, Dispatcher, types, F
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.storage.memory import MemoryStorage

TOKEN = os.getenv("BOT_TOKEN")
TIP_API_KEY = os.getenv("TIP_API_KEY")
ADMIN_ID = int(os.getenv("ADMIN_ID"))

TIP_REPORT_URL = "https://www.threat.rip/api/reports/file/{}"
TIP_CONFIG_URL = "https://www.threat.rip/api/reports/file/{}/config"
TIP_WEB_URL = "https://www.threat.rip/file/{}"

MAX_FILE_SIZE = 100 * 1024 * 1024
MAX_TG_FILE_SIZE = 20 * 1024 * 1024

TEMP_DIR = os.path.expanduser("~/threat_bot_temp")
os.makedirs(TEMP_DIR, exist_ok=True)

logging.basicConfig(level=logging.INFO)
storage = MemoryStorage()
bot = Bot(token=TOKEN)
dp = Dispatcher(storage=storage)

user_states = {}
user_reports = {}

class HealthCheckHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK')

def run_health_server():
    port = int(os.getenv('PORT', 10000))
    server = HTTPServer(('0.0.0.0', port), HealthCheckHandler)
    server.serve_forever()

threading.Thread(target=run_health_server, daemon=True).start()

def convert_direct_link(url: str) -> str:
    if 'dropbox.com' in url:
        url = re.sub(r'\?dl=0', '?dl=1', url)
        if 'dl=0' not in url and 'dl=1' not in url:
            url += '&dl=1' if '?' in url else '?dl=1'
        return url
    
    if 'drive.google.com' in url:
        file_id = None
        if '/file/d/' in url:
            file_id = url.split('/file/d/')[1].split('/')[0]
        elif 'id=' in url:
            file_id = parse_qs(urlparse(url).query).get('id', [None])[0]
        if file_id:
            return f"https://drive.google.com/uc?export=download&id={file_id}"
    
    return url

def get_file_size_from_url(url: str) -> int:
    try:
        head = requests.head(url, allow_redirects=True, timeout=10)
        return int(head.headers.get('content-length', 0))
    except:
        return 0

def download_file_from_url(url: str, file_path: str) -> bool:
    try:
        response = requests.get(url, stream=True, timeout=60)
        if response.status_code != 200:
            return False
        with open(file_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
        return True
    except:
        return False

def scanner_keyboard():
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔍 Сканер (файл)", callback_data="scanner")],
        [InlineKeyboardButton(text="🔗 Сканер (ссылка)", callback_data="scanner_url")]
    ])
    return keyboard

def result_keyboard(file_hash: str, is_ready: bool):
    if is_ready:
        keyboard = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="📊 Детекты", callback_data="get_detects"),
             InlineKeyboardButton(text="⚙️ Malware Config", callback_data="get_config")],
            [InlineKeyboardButton(text="🔄 Новое сканирование", callback_data="scanner")]
        ])
    else:
        keyboard = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🔄 Проверить готовность", callback_data="check_ready")],
            [InlineKeyboardButton(text="🔄 Новое сканирование", callback_data="scanner")]
        ])
    return keyboard

def check_report_ready(file_hash: str) -> bool:
    api_url = TIP_REPORT_URL.format(file_hash)
    headers = {"Authorization": TIP_API_KEY}
    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get('engineSummaries') or data.get('report', {}).get('threat_score', 0) > 0:
                return True
        return False
    except:
        return False

@dp.message(Command("start"))
async def cmd_start(message: types.Message):
    await message.answer(
        "👋 Добро пожаловать в сканер CoreDebuging!\n\n"
        "🔍 Я помогу проанализировать файлы\n"
        "📊 Получай детекты антивирусов и извлекай конфигурации\n\n"
        "👇 Выбери способ отправки файла:",
        reply_markup=scanner_keyboard()
    )

@dp.callback_query(F.data == "scanner")
async def process_scanner(callback: types.CallbackQuery, state: FSMContext):
    await callback.answer("✅ Режим загрузки файла")
    await state.clear()
    
    user_id = callback.from_user.id
    if user_id in user_reports:
        del user_reports[user_id]
    
    try:
        await callback.message.delete()
    except:
        pass
    
    await callback.message.answer(
        "📤 Отправьте файл для сканирования\n\n"
        "📁 Максимальный размер: 20 МБ\n"
        "📄 Поддерживаются: exe, dll, pdf, doc, zip, rar и другие\n\n"
        "Просто отправьте файл в этот чат."
    )
    user_states[callback.from_user.id] = 'waiting_for_file'

@dp.callback_query(F.data == "scanner_url")
async def process_scanner_url(callback: types.CallbackQuery, state: FSMContext):
    await callback.answer("🔗 Режим загрузки по ссылке")
    await state.clear()
    
    user_id = callback.from_user.id
    if user_id in user_reports:
        del user_reports[user_id]
    
    try:
        await callback.message.delete()
    except:
        pass
    
    await callback.message.answer(
        "🔗 Отправьте ссылку на файл\n\n"
        "📌 Для Dropbox: в конце ссылки замените dl=0 на dl=1\n"
        "   Пример: https://www.dropbox.com/s/...?dl=1\n\n"
        "📌 Для Google Drive: используйте публичную ссылку\n\n"
        "📌 Для других сервисов: прямая ссылка на файл\n\n"
        "📁 Максимальный размер: 100 МБ\n\n"
        "Пример: https://example.com/file.exe"
    )
    user_states[callback.from_user.id] = 'waiting_for_url'

@dp.callback_query(F.data == "check_ready")
async def check_ready(callback: types.CallbackQuery, state: FSMContext):
    await callback.answer("🔍 Проверяю готовность...")
    
    user_id = callback.from_user.id
    report_data = user_reports.get(user_id)
    
    if not report_data or not report_data.get('hash'):
        await callback.answer("❌ Нет активного файла", show_alert=True)
        return
    
    file_hash = report_data['hash']
    
    last_check = report_data.get('last_check', 0)
    if time.time() - last_check < 30:
        await callback.answer("⏳ Подождите 30 секунд перед следующей проверкой", show_alert=True)
        return
    
    user_reports[user_id]['last_check'] = time.time()
    
    if check_report_ready(file_hash):
        user_reports[user_id]['ready'] = True
        
        await callback.message.edit_text(
            f"✅ Отчет готов!\n\n"
            f"📄 Файл: {report_data.get('filename', 'N/A')}\n"
            f"🔑 SHA256: {file_hash[:16]}...{file_hash[-16:]}\n\n"
            f"📊 Теперь доступны детекты и конфигурация",
            reply_markup=result_keyboard(file_hash, True)
        )
    else:
        await callback.answer("⏳ Отчет еще не готов. Попробуйте через 1-2 минуты", show_alert=True)

@dp.callback_query(F.data == "get_detects")
async def get_detects(callback: types.CallbackQuery, state: FSMContext):
    user_id = callback.from_user.id
    report_data = user_reports.get(user_id)
    
    if not report_data or not report_data.get('ready'):
        await callback.answer("❌ Отчет еще не готов! Нажмите 'Проверить готовность'", show_alert=True)
        return
    
    file_hash = report_data['hash']
    api_url = TIP_REPORT_URL.format(file_hash)
    headers = {"Authorization": TIP_API_KEY}
    
    await callback.answer("📊 Получаю данные...")
    
    try:
        response = requests.get(api_url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            report = data.get('report', {})
            engines = data.get('engineSummaries', [])
            
            text = f"📊 РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ\n\n"
            text += f"📄 Файл: {report.get('file_name', 'N/A')}\n"
            text += f"🦠 Угроза: {report.get('threatName', 'N/A')}\n"
            text += f"⚖️ Вердикт: {report.get('verdict', 'N/A')}\n"
            text += f"📊 Скор: {report.get('threat_score', 'N/A')}/100\n\n"
            
            if engines:
                text += f"🔍 AV Детекты ({len(engines)} сканеров):\n\n"
                for eng in engines:
                    vendor = eng.get('vendor', 'Unknown')
                    verdict = eng.get('verdict', 'N/A')
                    score = eng.get('score', '')
                    info = eng.get('info', '')
                    
                    if verdict == "MALICIOUS":
                        icon = "🔴"
                    elif verdict == "SUSPICIOUS":
                        icon = "⚠️"
                    elif verdict == "CLEAN":
                        icon = "✅"
                    else:
                        icon = "❓"
                    
                    text += f"{icon} {vendor}: {verdict}"
                    if score:
                        text += f" (score: {score})"
                    text += f"\n"
                    if info:
                        text += f"   └─ {info[:80]}\n"
                    text += f"\n"
            else:
                text += "ℹ️ Нет данных от AV сканеров\n\n"
            
            tags = data.get('tags', [])
            if tags:
                text += f"🏷️ Теги:\n"
                for tag in tags[:10]:
                    text += f"• {tag.get('tag', 'N/A')} (confidence: {tag.get('score', 0)})\n"
                text += f"\n"
            
            text += f"📦 Размер: {report.get('file_size', 0):,} байт\n"
            text += f"📄 Тип: {report.get('file_type', 'N/A')}\n"
            
            if user_id == ADMIN_ID:
                text += f"\n🔗 Полный отчет: {TIP_WEB_URL.format(file_hash)}"
            
            await callback.message.edit_text(text, reply_markup=result_keyboard(file_hash, True))
        else:
            await callback.answer(f"⚠️ Ошибка {response.status_code}", show_alert=True)
            
    except Exception as e:
        logging.error(f"Detects error: {e}")
        await callback.answer(f"❌ Ошибка: {str(e)[:30]}", show_alert=True)

@dp.callback_query(F.data == "get_config")
async def get_config(callback: types.CallbackQuery, state: FSMContext):
    user_id = callback.from_user.id
    report_data = user_reports.get(user_id)
    
    if not report_data or not report_data.get('ready'):
        await callback.answer("❌ Отчет еще не готов! Нажмите 'Проверить готовность'", show_alert=True)
        return
    
    file_hash = report_data['hash']
    config_url = TIP_CONFIG_URL.format(file_hash)
    headers = {"Authorization": TIP_API_KEY}
    
    await callback.answer("⚙️ Получаю конфигурацию...")
    
    try:
        response = requests.get(config_url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            text = f"⚙️ MALWARE CONFIGURATION\n\n"
            
            c2_list = []
            config_data = {}
            
            for item in data:
                if 'config' in item:
                    try:
                        config_str = item['config']
                        if isinstance(config_str, str):
                            parsed = json.loads(config_str)
                            if 'config' in parsed:
                                config_data = parsed['config']
                            elif isinstance(parsed, list):
                                for p in parsed:
                                    if 'host' in p:
                                        c2_list.append(p)
                            else:
                                config_data = parsed
                    except:
                        pass
            
            if config_data:
                attr = config_data.get('attr', {})
                if attr:
                    text += f"📁 Установка:\n"
                    for k, v in attr.items():
                        text += f"• {k}: {v}\n"
                    text += "\n"
                
                family = config_data.get('family', '')
                if family:
                    text += f"🦠 Семейство: {family}\n"
                
                version = config_data.get('version', '')
                if version:
                    text += f"📌 Версия: {version}\n"
            
            if c2_list:
                text += f"\n🎯 C2 Серверы:\n"
                for c2 in c2_list:
                    host = c2.get('host', 'N/A')
                    port = c2.get('port', '')
                    proto = c2.get('protocol', '')
                    rep = c2.get('reputation', '')
                    
                    if port:
                        text += f"• {host}:{port}"
                    else:
                        text += f"• {host}"
                    if proto:
                        text += f" ({proto})"
                    text += f"\n"
                    if rep:
                        text += f"  └─ Репутация: {rep}\n"
            
            if not config_data and not c2_list:
                text += "ℹ️ Конфигурация не найдена\n"
            
            if user_id == ADMIN_ID:
                text += f"\n🔗 Полный отчет: {TIP_WEB_URL.format(file_hash)}"
            
            await callback.message.edit_text(text, reply_markup=result_keyboard(file_hash, True))
        else:
            await callback.answer(f"⚠️ Ошибка {response.status_code}", show_alert=True)
            
    except Exception as e:
        logging.error(f"Config error: {e}")
        await callback.answer(f"❌ Ошибка: {str(e)[:30]}", show_alert=True)

def upload_to_tip(file_path: str, filename: str) -> dict:
    headers = {"Authorization": TIP_API_KEY}
    try:
        with open(file_path, 'rb') as f:
            files = {'file': (filename, f)}
            response = requests.post(
                "https://www.threat.rip/api/upload/file",
                headers=headers,
                files=files,
                timeout=30
            )
            if response.status_code == 200:
                return {"success": True, "hash": response.text.strip()}
            elif response.status_code == 409:
                try:
                    data = json.loads(response.text)
                    return {"success": True, "hash": data.get('optional', ''), "exists": True}
                except:
                    return {"success": True, "hash": response.text.strip(), "exists": True}
            else:
                return {"success": False, "error": response.text}
    except Exception as e:
        return {"success": False, "error": str(e)}

def upload_file_from_url(url: str, filename: str) -> dict:
    try:
        direct_url = convert_direct_link(url)
        file_size = get_file_size_from_url(direct_url)
        if file_size > MAX_FILE_SIZE:
            return {"success": False, "error": f"Файл превышает 100 МБ"}
        
        if not filename or filename == 'file' or '.' not in filename:
            filename = url.split('/')[-1].split('?')[0] or 'file.exe'
        
        file_path = os.path.join(TEMP_DIR, filename)
        if not download_file_from_url(direct_url, file_path):
            return {"success": False, "error": "Не удалось скачать файл по ссылке"}
        
        result = upload_to_tip(file_path, filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        return result
    except Exception as e:
        return {"success": False, "error": str(e)}

@dp.message()
async def handle_messages(message: types.Message, state: FSMContext):
    user_id = message.from_user.id
    state_type = user_states.get(user_id)
    
    if state_type == 'waiting_for_file':
        if not message.document:
            await message.answer("❌ Отправьте файл, а не текст")
            return
        
        document = message.document
        if document.file_size > MAX_TG_FILE_SIZE:
            await message.answer(f"❌ Файл превышает 20 МБ. Используйте 'Сканер (ссылка)' для больших файлов.")
            return
        
        status_msg = await message.answer("⏳ Загружаю файл...")
        file_path = os.path.join(TEMP_DIR, document.file_name)
        
        try:
            file = await bot.get_file(document.file_id)
            await bot.download_file(file.file_path, file_path)
            
            await status_msg.edit_text("📤 Отправляю на анализ...")
            result = upload_to_tip(file_path, document.file_name)
            
            if not result["success"]:
                await status_msg.edit_text(f"❌ Ошибка:\n{result.get('error')}")
                return
            
            file_hash = result.get("hash")
            if not file_hash:
                await status_msg.edit_text("❌ Не удалось получить хеш")
                return
            
            user_reports[user_id] = {
                'hash': file_hash,
                'filename': document.file_name,
                'ready': False,
                'last_check': 0
            }
            
            await status_msg.edit_text(
                f"✅ Файл загружен, ожидайте анализа\n\n"
                f"📄 Файл: {document.file_name}\n"
                f"🔑 SHA256: {file_hash[:16]}...{file_hash[-16:]}\n\n"
                f"🔄 Анализ занимает 1-5 минут.\n"
                f"Нажмите 'Проверить готовность' когда отчет появится",
                reply_markup=result_keyboard(file_hash, False)
            )
            
        except Exception as e:
            await status_msg.edit_text(f"❌ {str(e)}")
        finally:
            if os.path.exists(file_path):
                os.remove(file_path)
            user_states[user_id] = None
    
    elif state_type == 'waiting_for_url':
        url = message.text.strip()
        if not url.startswith(('http://', 'https://')):
            await message.answer("❌ Пожалуйста, отправьте корректную ссылку (http:// или https://)")
            return
        
        status_msg = await message.answer("⏳ Обрабатываю ссылку...")
        
        filename = url.split('/')[-1].split('?')[0]
        if not filename or '.' not in filename:
            filename = 'file.exe'
        
        try:
            result = upload_file_from_url(url, filename)
            
            if not result["success"]:
                await status_msg.edit_text(f"❌ Ошибка:\n{result.get('error')}")
                return
            
            file_hash = result.get("hash")
            if not file_hash:
                await status_msg.edit_text("❌ Не удалось получить хеш")
                return
            
            user_reports[user_id] = {
                'hash': file_hash,
                'filename': filename,
                'ready': False,
                'last_check': 0
            }
            
            await status_msg.edit_text(
                f"✅ Файл загружен, ожидайте анализа\n\n"
                f"📄 Файл: {filename}\n"
                f"🔑 SHA256: {file_hash[:16]}...{file_hash[-16:]}\n\n"
                f"🔄 Анализ занимает 1-5 минут.\n"
                f"Нажмите 'Проверить готовность' когда отчет появится",
                reply_markup=result_keyboard(file_hash, False)
            )
            
        except Exception as e:
            await status_msg.edit_text(f"❌ {str(e)}")
        finally:
            user_states[user_id] = None
    
    else:
        await message.answer(
            "👋 Добро пожаловать в сканер CoreDebuging!\n\n"
            "🔍 Нажми /start для начала работы",
            reply_markup=scanner_keyboard()
        )

if __name__ == '__main__':
    import asyncio
    import time
    import threading
    import requests
    
    time.sleep(2)
    
    def self_pinger():
        port = os.getenv('PORT', 10000)
        url = f"http://localhost:{port}"
        while True:
            time.sleep(240)
            try:
                requests.get(url, timeout=5)
            except:
                pass
    
    threading.Thread(target=self_pinger, daemon=True).start()
    
    asyncio.run(dp.start_polling(bot))
