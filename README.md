# Home SIEM Lab — Wazuh + Suricata на Apple Silicon

> Портфолио-проект: построение домашней лаборатории SIEM с нуля на ARM64 (Apple Silicon M-series), симуляция реальных атак и их детекция.

---

## Содержание

- [Обзор проекта](#обзор-проекта)
- [Архитектура](#архитектура)
- [Стек технологий](#стек-технологий)
- [Установка и настройка](#установка-и-настройка)
- [Сценарии атак и детекция](#сценарии-атак-и-детекция)
- [Ключевые результаты](#ключевые-результаты)
- [Технические особенности ARM64](#технические-особенности-arm64)

---

## Обзор проекта

Этот проект демонстрирует построение полноценной SIEM-лаборатории в домашних условиях с использованием Wazuh, Suricata и Logstash. Лаборатория развёрнута на **VMware Fusion на Mac с Apple Silicon (aarch64)** — нестандартная платформа, потребовавшая ручной установки всех компонентов из-за несовместимости официальных установщиков с ARM64.

**Цели проекта:**
- Изучить архитектуру SIEM на практике
- Симулировать реальные атаки (brute-force, сканирование, подозрительные процессы, изменение критических файлов)
- Настроить автоматическое реагирование на инциденты
- Получить практический опыт с MITRE ATT&CK

---

## Архитектура

```
┌─────────────────────────────────────────────────────┐
│                  Mac (Apple Silicon)                 │
│                  Хост / Браузер                      │
│              https://127.0.0.1 (dashboard)           │
└──────────────────────┬──────────────────────────────┘
                       │ VMware Fusion
          ┌────────────┴────────────┐
          │      siem-lab network   │
          │     192.168.212.0/24    │

          └──┬──────────┬───────────┘
             │          │           │
    ┌────────┴──┐ ┌─────┴──────┐ ┌─┴──────────┐
    │ wazuh-srv │ │ ubuntu-agt │ │  kali-atk  │
    │.212.10    │ │.212.20     │ │.212.40     │
    │           │ │            │ │            │
    │ Wazuh     │ │ Wazuh      │ │ Hydra      │
    │ Indexer   │ │ Agent      │ │ Nmap       │
    │ Manager   │ │ Suricata   │ │ Netcat     │
    │ Dashboard │ │ Auditd     │ │            │
    │ Logstash  │ │            │ │            │
    └───────────┘ └────────────┘ └────────────┘
```

### Виртуальные машины

| VM | ОС | IP (siem-lab) | Роль |
|----|----|---------------|------|
| wazuh-srv | Ubuntu 20.04 | 192.168.212.10 | SIEM сервер |
| ubuntu-agt | Ubuntu 20.04 | 192.168.212.20 | Жертва / агент |
| kali-atk | Kali Linux | 192.168.212.40 | Атакующий |

---

## Стек технологий

| Компонент | Версия | Назначение |
|-----------|--------|------------|
| Wazuh Indexer | 4.14.5 | Хранение и индексация алертов (OpenSearch) |
| Wazuh Manager | 4.14.5 | Анализ логов, применение правил |
| Wazuh Dashboard | 4.14.5 | Визуализация, MITRE ATT&CK mapping |
| Wazuh Agent | 4.14.5 | Сбор логов на ubuntu-agt |
| Suricata | 8.x | IDS — сетевая детекция |
| Logstash | 8.9.0 (OSS) | Парсинг и отправка алертов в индекс |
| Auditd | — | Мониторинг системных вызовов |
| VMware Fusion | — | Виртуализация на Apple Silicon |

---

## Установка и настройка

### Ключевые решения для ARM64

Официальный установщик `wazuh-install.sh` **не поддерживает ARM64** — проверяет только `x86_64`. Все компоненты установлены вручную в порядке:

```
wazuh-indexer → wazuh-manager → wazuh-dashboard
```

**APT репозиторий с явным указанием архитектуры:**
```bash
echo "deb [arch=arm64 signed-by=/usr/share/keyrings/wazuh.gpg] \
  https://packages.wazuh.com/4.x/apt/ stable main" \
  | sudo tee /etc/apt/sources.list.d/wazuh.list
```

**Замена Filebeat на Logstash** из-за несовместимости Filebeat с OpenSearch 2.x (`_type` в Bulk API):
```bash
# Использован logstash-oss-with-opensearch-output-plugin-8.9.0-linux-arm64
```

**Обязательный фикс Logstash конфига:**
```ruby
filter {
  mutate {
    remove_field => ["host"]  # без этого mapper_parsing_exception
  }
}
```

### Сетевая конфигурация

Доступ к дашборду с Mac через port forwarding в VMware Fusion:
```
# /Library/Preferences/VMware Fusion/vmnet8/nat.conf
443 = 192.168.212.10:443
```

---

## Сценарии атак и детекция

### Сценарий A — Nmap SYN Scan
**Атака:** Сканирование портов ubuntu-agt с kali-atk  
**Инструмент:** `nmap -sS 192.168.212.20`  
**Детекция:** Suricata ET SCAN rules  
**Результат:** `ET SCAN Possible Nmap User-Agent Observed` (Rule 86601)

---

### Сценарий B — SSH Brute-Force 🔴
**Атака:** Перебор паролей SSH на ubuntu-agt  
**Инструмент:** `hydra -l testuser -P wordlist.txt ssh://192.168.212.20`  
**Детекция:** Wazuh агрегирующее правило после 8+ неудачных попыток  
**Результат:** Rule **5763** `sshd: brute force trying to get access` — **Level 10**  
**MITRE:** T1110 — Brute Force / Credential Access

```
[Kali] hydra → [ubuntu-agt:22] → sshd logs → [Wazuh Agent]
→ [Wazuh Manager] → Rule 5763 (Level 10) → [Dashboard]
```

---

### Сценарий C — Suspicious Process (Netcat) 🔴
**Атака:** Запуск netcat на ubuntu-agt (симуляция reverse shell)  
**Инструмент:** `nc -zv 192.168.212.10 443`  
**Детекция:** Auditd (execve syscall) + кастомное правило Wazuh  
**Результат:** Rule **100001** `Suspicious: netcat executed` — **Level 10**  
**MITRE:** T1059 — Command and Scripting Interpreter

**Кастомное правило** (`/var/ossec/etc/rules/local_rules.xml`):
```xml
<group name="audit,">
  <rule id="100001" level="10">
    <if_sid>80700</if_sid>
    <match>exe="/usr/bin/nc</match>
    <description>Suspicious: netcat executed on $(agent.name)</description>
    <mitre>
      <id>T1059</id>
    </mitre>
  </rule>
</group>
```

---

### Сценарий D — File Integrity Monitoring 🟡
**Атака:** Добавление пользователя и модификация `/etc/sudoers`  
**Инструменты:** `useradd hacker123`, `echo "hacker123 ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers`  
**Детекция:** Wazuh FIM (syscheck) с realtime мониторингом  
**Результат:** Rule **550** `Integrity checksum changed` — **Level 7**

**Конфигурация FIM** (`/var/ossec/etc/shared/default/agent.conf`):
```xml
<agent_config>
  <syscheck>
    <directories check_all="yes" report_changes="yes" realtime="yes">
      /etc/passwd,/etc/shadow,/etc/sudoers
    </directories>
    <directories check_all="yes" report_changes="yes" realtime="yes">
      /root
    </directories>
  </syscheck>
</agent_config>
```

---

### Active Response — Автоблокировка IP 🔴
**Триггер:** Rule 5763 (SSH brute-force, Level 10)  
**Действие:** `firewall-drop` — автоматический DROP через iptables  
**Timeout:** 300 секунд  
**Результат:** Rule **651** `Host Blocked by firewall-drop Active Response`

```
Rule 5763 срабатывает
→ Wazuh Manager отправляет команду агенту
→ firewall-drop скрипт выполняется на ubuntu-agt
→ iptables -I INPUT -s 192.168.212.40 -j DROP
→ kali-atk заблокирован на 5 минут
```

**Конфигурация** (`/var/ossec/etc/ossec.conf`):
```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>5763</rules_id>
  <timeout>300</timeout>
</active-response>
```

**Подтверждение блокировки:**
```
$ sudo iptables -L INPUT -n | grep 192.168.212.40
DROP  all  --  192.168.212.40  0.0.0.0/0
```

---

## Ключевые результаты

| # | Сценарий | Инструмент атаки | Rule ID | Level | MITRE |
|---|----------|-----------------|---------|-------|-------|
| A | Nmap scan | nmap -A -T4 | 86601 | 3 | T1046 |
| B | SSH Brute-force | hydra | 5763 | **10** | T1110 |
| C | Netcat (reverse shell) | nc | 100001 | **10** | T1059 |
| D | sudoers modification | useradd / echo | 550 | 7 | T1548 |
| AR | Auto IP block | — | 651 | 3 | — |
| E | Suricata Nmap detect | nmap | 86601 | 3 | T1046 |

---

## Технические особенности ARM64

Работа на Apple Silicon потребовала нескольких нестандартных решений:

1. **Официальный установщик не работает** — `wazuh-install.sh` проверяет `x86_64`, падает на aarch64. Ручная установка обязательна.

2. **Filebeat несовместим с OpenSearch 2.x** — использует устаревший `_type` в Bulk API. Заменён на Logstash с `opensearch-output-plugin`.

3. **auditd `-w` watch на файлы** работает нестабильно на ARM64 — заменён на `-a always,exit -F arch=b64 -S execve`.

4. **VMware Fusion NAT** не форвардит порты автоматически — требует ручного редактирования `nat.conf`.

5. **Диск заполняется** от `/var/ossec/queue/vd/event/LOG` (deleted file held open) — решается через `lsof +L1` и `rm -rf /var/ossec/queue/vd/`.

---

## Структура репозитория

```
wazuh-siem-lab/
├── README.md                    # этот файл
├── configs/
│   ├── wazuh-srv/
│   │   ├── ossec.conf           # конфиг менеджера
│   │   ├── local_rules.xml      # кастомные правила
│   │   └── logstash-wazuh.conf  # pipeline Logstash
│   └── ubuntu-agt/
│       ├── ossec.conf           # конфиг агента
│       └── agent.conf           # shared config (FIM)
└── screenshots/
    ├── 01-dashboard-overview.png
    ├── 02-ssh-brute-force-rule5763.png
    ├── 03-active-response-rule651.png
    ├── 04-netcat-rule100001.png
    ├── 05-fim-rule550.png
    └── 06-suricata-nmap.png
```

---

*Проект выполнен в учебных целях в изолированной виртуальной среде.*
