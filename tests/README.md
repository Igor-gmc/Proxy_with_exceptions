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

Settings.Tests проверяет пустой профиль, отсутствие автоматического создания
настроек, валидацию, DPAPI roundtrip и повреждение файла в отдельной подпапке
artifacts. Рабочие настройки и сеть не меняются. Остальные hosts проверяют
буферизацию журналов, модель активности, диагностические события и управление
дочерней консолью. EngineConsole.Tests запускает собственный тестовый процесс.
Они не поднимают рабочий TUN; успешные результаты не доказывают отсутствие утечек.

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
