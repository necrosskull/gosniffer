# gosniffer

## Захват и сохранение пакетов

Эта программа на Go позволяет захватывать сетевые пакеты на указанном интерфейсе, применять фильтры и сохранять захваченные пакеты в файлы формата PCAP.

## Важно ❗❗❗

Для работы программы на Windows необходимо установить [Npcap](<https://nmap.org/npcap>)

Для работы программы на Linux необходимо установить libpcap-dev

```bash
sudo apt install -y libpcap-dev
```

### Флаги командной строки

- `-i`: Указывает сетевой интерфейс для захвата пакетов.
- `-d`: Указывает директорию для сохранения файлов PCAP.
- `-f`: Устанавливает фильтр BPF для захвата определенных пакетов.
- `-s`: Устанавливает максимальный размер пакета для захвата.
- `-p`: Включает режим promiscuous.
- `-t`: Устанавливает таймаут для захвата пакетов.

### Пример использования

Установить зависимости:

```bash
go mod tidy
```

Собрать программу:

```bash
go build -o gosniffer.exe main.go
```

Запустить программу:

```bash
.\gosniffer.exe --i Ethernet --d pcapdir
```

В результате при завершении программы в директории `pcapdir` будет сохранен файл PCAP с захваченными пакетами.

### Пример запуска из Python

```python
import signal
import subprocess
import sys
import time

gosniffer_path = "gosniffer.exe"
inerface = "Ethernet"
directory = "pcapdir"

parameters = ["--i", inerface, "--d", directory]
process = subprocess.Popen([gosniffer_path] + parameters)


time.sleep(5)

if sys.platform == "win32":
    process.send_signal(signal.CTRL_BREAK_EVENT)
else:
    process.send_signal(signal.SIGINT)
```

При запуске этого скрипта будет запущен `gosniffer.exe`, который будет захватывать пакеты на интерфейсе `Ethernet` и сохранит их в директорию `pcapdir` через 5 секунд после запуска.
