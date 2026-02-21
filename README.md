# RC4+XOR .NET Crypter — YARA Rules & Decryptor

[🇷🇺 Читать на русском языке](#описание-на-русском)

Detection rules and an automatic decryptor for a .NET Core / .NET Framework crypter/dropper family. This malware uses a modified RC4 algorithm with double-XOR to decrypt and execute embedded payloads.

## Crypter Architecture

```text
┌──────────────────────────────────────────────┐
│  .NET Core 8.0 Single-File EXE (25-45MB)     │
│  OR traditional .NET Framework EXE           │
│  ┌─────────────────────────────────────────┐ │
│  │  p.dll (Inner .NET DLL / Core Logic)    │ │
│  │  ┌───────────────────────────────────┐  │ │
│  │  │ 1. Hide Console Window            │  │ │
│  │  │    ShowWindow(GetConsoleWindow()) │  │ │
│  │  │                                   │  │ │
│  │  │ 2. Extract Embedded Resource "r"  │  │ │
│  │  │    GetManifestResourceStream("r") │  │ │
│  │  │                                   │  │ │
│  │  │ 3. Extract 16-byte Key from IL    │  │ │
│  │  │    (via stelem or InitializeArray)│  │ │
│  │  │                                   │  │ │
│  │  │ 4. Decrypt via RC4 + XOR          │  │ │
│  │  │                                   │  │ │
│  │  │ 5. Drop payload to disk           │  │ │
│  │  │    WriteAllBytes(TEMP\File.exe)   │  │ │
│  │  │                                   │  │ │
│  │  │ 6. Execute payload                │  │ │
│  │  │    Process.Start()                │  │ │
│  │  └───────────────────────────────────┘  │ │
│  └─────────────────────────────────────────┘ │
└──────────────────────────────────────────────┘
```

The 16-byte RC4 key changes per sample. The decryption algorithm, structure, and API call chain remain invariant across variants.

---

## The Decryptor Tool (`decryptor.exe`)

The included `decryptor` tool is written in C# (.NET 4.8) and is completely automated. It performs the following heuristic operations:

1. **Format Detection**: Checks if the target is a large .NET Core Single-File Bundle (>5MB). If it is, the decryptor parses the manifest headers to extract the internal `p.dll` core logic file dynamically without executing the malware.
2. **Resource Extraction**: Uses .NET Reflection (`Assembly.Load`) in memory to search for embedded resources and automatically extracts the encrypted payload (usually named `"r"`).
3. **Key Extraction**: Analyzes the raw bytes of the core DLL to find the 16-byte RC4 key. It supports two different compiler optimizations used by the malware authors:
   - **`stelem` Pattern**: Reads IL opcode patterns (`1F 10 8D ...`) looking for Array initialization done element-by-element.
   - **`InitializeArray` Pattern**: Uses Reflection to scan `<PrivateImplementationDetails>` fields and extracts the key directly from the `RuntimeHelpers.InitializeArray` memory handle.
4. **Decryption**: Applies the modified RC4 double-XOR algorithm and drops the final `decrypted.exe` payload to disk.

### Usage
```cmd
decryptor.exe <crypter.exe>
```

---

## Detection Logic & YARA Rules

### Invariant Patterns Used
The crypter relies on a specific sequence of API calls (present in .NET metadata) and a custom RC4 implementation:
- `ShowWindow` + `GetConsoleWindow` — console hiding via P/Invoke
- `GetManifestResourceStream` + `GetExecutingAssembly` — payload extraction
- `WriteAllBytes` — writing to disk
- `ProcessStartInfo` + `UseShellExecute` — payload execution

### Custom RC4 Double-XOR Signature
The PRGA (Pseudo-Random Generation Algorithm) of the RC4 used here is highly modified. Standard RC4 uses a single XOR. This variant uses a **double XOR** against both the keystream and the static key array:
```
result[i] = data[i] ^ keystream_byte ^ key[i % key.Length]
```

This IL bytecode anomaly creates a strong, invariant signature used in the `RC4XOR_Crypter_Generic` rule:
```yara
; Hex pattern (19 bytes):
; 91 58 20 00 01 00 00 5D 91 61 ?? ?? ?? ?? ?? ?? 5D 91 61
;      │                 │     │                  │     │
;      add        ldc.i4(256) xor           rem(256)   xor  ← double XOR = modified RC4
```

---

## Known Samples

| SHA-256 | Notes |
|---------|-------|
| `59e65bab71bd3a756342b210819c4e177cc4453b5caedb54b358818f9e1b889b` | .NET Core 8.0 bundle |
| `b0fdca763fa2cb65173974740dcf6869d3c66cae3abecfb6e1f33158ddf8fc7b` | .NET Core 8.0 bundle |

---
---

# Описание на русском

YARA-правила и инструмент для автоматической дешифровки файлов семейства .NET Core / .NET Framework криптеров (дропперов). Данное ВПО использует модифицированный алгоритм RC4 с двойным XOR для дешифровки и запуска вшитой полезной нагрузки.

## Архитектура Криптера

Криптер обычно представляет собой `Single-File EXE` бандл на базе .NET Core (размером от 25 до 45 МБ) или классический .NET Framework EXE.

Внутри бандла находится библиотека (чаще всего `p.dll`), которая выполняет основную работу:
1. Скрывает консольное окно жертвы с помощью P/Invoke функций `ShowWindow` и `GetConsoleWindow`.
2. Извлекает зашифрованный пейлоад из своих собственных ресурсов (ресурс с именем `"r"`).
3. Выделяет памяти и инициализирует 16-байтный ключ.
4. Расшифровывает данные с помощью нестандартного RC4.
5. Сохраняет расшифрованный PE-файл на диск (обычно в папку `TEMP`).
6. Запускает его через `Process.Start`.

Ключ обфускации меняется от сэмпла к сэмплу. Дешифратор ищет именно инвариантные (неизменные) паттерны IL-кода.

---

## Как работает Дешифратор (`decryptor.exe`)

Утилита написана на C# (.NET 4.8) и работает полностью автономно. 

Принцип работы по шагам:
1. **Распаковка Бандла**: Приложение проверяет размер файла. Если это 40-мегабайтный .NET Core бандл, дешифратор самостоятельно парсит манифест внутри бинарника, находит смещения и извлекает модуль `p.dll` в память без запуска самого малвари.
2. **Извлечение Ресурса**: Приложение "на лету" подгружает DLL через Reflection (`Assembly.Load`), сканирует манифест ресурсов, находит ресурс `"r"` и считывает зашифрованные байты полезной нагрузки.
3. **Автоматический Поиск Ключа**: Инструмент сканирует байты `p.dll` на наличие 16-байтного ключа. Поддерживается обход двух разных приемов компилятора:
   - **Через `stelem`**: Сканируется IL-байткод в поисках инструкций поэлементного заполнения массива.
   - **Через `InitializeArray`**: Ищется внутренний служебный класс `<PrivateImplementationDetails>`, откуда ключ вытягивается через `RuntimeHelpers.InitializeArray`.
4. **Дешифровка**: Файл расшифровывается через тот самый "двойной XOR" и сохраняется рядом как `decrypted.exe`.

### Использование
```cmd
decryptor.exe <crypter.exe>
```

---

## Логика Детектирования (YARA)

Детекты (папка с YARA правилами) строятся не вокруг ключей или хешей, а вокруг поведения, заложенного в IL-код сборки.

### Уникальный паттерн RC4 (Двойной XOR)
Классический поточный шифр RC4 использует только одну операцию XOR между байтом данных и байтом ключевого потока. Однако в этом криптере применяется нестандартная формула — добавляется второй XOR непосредственно со статичным ключом, циклически (mod Length):
```
result[i] = data[i] ^ keystream_byte ^ key[i % key.Length]
```
Эта необычная формула компилируется в весьма специфичный IL-байткод (включая две операции `xor` в рамках алгоритма генерации). Правила `RC4XOR_Crypter_*` ищут именно эту 19-байтную последовательность байткода, что почти полностью исключает ложные срабатывания (False Positives) на легитимном софте, который может содержать обычный RC4.
