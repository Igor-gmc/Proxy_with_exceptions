# Проверки ProxyBridge

После восстановления зависимостей и сборки из корня проекта:

```powershell
dotnet run --project tests/Core.Tests -c Release
dotnet run --project tests/Settings.Tests -c Release
dotnet run --project tests/Logging.Tests -c Release
dotnet run --project tests/Activity.Tests -c Release
dotnet run --project tests/Diagnostics.Tests -c Release
dotnet run --project tests/EngineConsole.Tests -c Release
```

Core.Tests проверяет lifecycle через fake-операции, JSON-конфигурацию по четырём
эталонам исходной версии, готовность TUN, разбор CLI, тестовые HTTPS-ответы и
отсутствие тестовых типов в рабочей сборке. Native Guard в этом хосте запрещён.
Адресные проверки покрывают нормализацию IP/CIDR, границы подсетей, сочетания
адреса и порта, DNS-приоритет, IPv6 fallback и сохранение прежних EXE-правил.

Settings.Tests проверяет пустой профиль, отсутствие автоматического создания
настроек, валидацию, DPAPI roundtrip и повреждение файла в отдельной подпапке
artifacts. Рабочие настройки и сеть не меняются. Остальные hosts проверяют
буферизацию журналов, модель активности, диагностические события и управление
дочерней консолью. EngineConsole.Tests запускает собственный тестовый процесс.
Они не поднимают рабочий TUN; успешные результаты не доказывают отсутствие утечек.

## Адресные правила и native ABI без изменения сети

После `build.ps1`, из корня, с новым каталогом результатов:

```powershell
dotnet run --project tests/GuardAbi.Tests -c Release -- dist/ProxyGuard.dll artifacts/address-abi-check
```

Хост проверяет реальный managed/native массив V5, размер 28 байт и отказы на
неверной второй записи. В свежем процессе вызывается только `GuardMatchesV5`
с ненулевым LUID без активной сессии: после построения политики вызов возвращает
false до открытия BFE. Configure, Remove и Deactivate не вызываются.

В x64 Developer Command Prompt можно собрать чистые native-проверки:

```bat
cl /nologo /MT /EHsc /std:c++17 /W4 /O2 tests\address-policy-tests.cpp /Fo:artifacts\address-policy-tests.obj /link /OUT:artifacts\address-policy-tests.exe
artifacts\address-policy-tests.exe "%CD%\vendor\sing-box-1.14.4-windows-amd64\sing-box.exe"
```

Они проверяют настоящий builder/comparator и синтетические потоки, не открывая
BFE и не отправляя трафик. Для identity используется существующий EXE.
Принятие фильтров Windows, маршруты LAN/TUN, открытые соединения и антивирус
этими тестами не проверяются. `guard-policy-tests.cpp` использует WFP с откатом:
его запускает только координатор при закрытом рабочем приложении.

## Проверка интерфейса

```powershell
dotnet build ProxyBridge.slnx -c Release
dotnet tests/DesignPreview/bin/Release/net10.0-windows/DesignPreview.dll --dll ABSOLUTE_PATH_TO_ProxyBridge.dll --test-host ABSOLUTE_PATH_TO_ProxyBridge.TestHost.dll --out ABSOLUTE_NEW_OUTPUT --verify
```

Укажите DLL приложения и TestHost из одной сборки и новый каталог артефактов.
DLL тестового хоста находится в `tests/TestHost/bin/Release/net10.0-windows/`.
Она нужна только renderer с `--verify`, рабочее приложение её не загружает.
Renderer использует только
синтетические настройки, не запускает обычную точку входа и запрещает загрузку
нативного Guard. Проверяются переходы интерфейса и перерисовка углов кнопок.
Снимки не являются доказательством реального сетевого подключения.

## Полный автоматический прогон

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File build.ps1 -BuildOnly -IncludeTests
powershell -NoProfile -ExecutionPolicy Bypass -File tests/run-tests.ps1
```

Runner запускает `artifacts/test-host/ProxyBridge.TestHost.exe` и копирует его
в отдельный каталог прогона. Параметр `-Executable` теперь принимает именно
TestHost, не пользовательский ProxyBridge EXE. В рабочем EXE тестовые флаги
возвращают отказ; код тестов в него не компилируется.

Только из административной консоли при закрытом ProxyBridge. Runner откажется
работать рядом с активным приложением и не завершает его автоматически.
Проверки bundle/self/UI используют собственные данные. Self-test обращается
к WFP внутри транзакции с откатом; не запускайте его одновременно с сетевыми
операциями приложения. Команда --network-test отключена до доработки владения
тестовой защитой. Прямой вызов отключённого теста не поддерживается.

## Результаты

PASS — выполнена конкретная проверка; FAIL — нарушено её условие; SKIP —
не выполнена с указанием причины. Живые сетевые сценарии находятся в integration.
Исторические отчёты и снимки в Git не публикуются: они могут содержать сведения
о компьютере и сети. Новые результаты сохраняйте только в artifacts.
