@echo off
echo Запуск Google Chrome с поддержкой чтения сертификатов для CA Indicator...
start "" "chrome.exe" --enable-features=WebRequestSecurityInfo
echo Запущено! Теперь откройте сайт (например, https://google.com) и проверьте значок CA Indicator.
