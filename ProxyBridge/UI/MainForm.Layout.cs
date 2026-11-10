namespace ProxyBridge;

internal sealed partial class MainForm
{
    readonly Dictionary<string, Control> pages = new(StringComparer.Ordinal);
    readonly Dictionary<string, Button> navigation = new(StringComparer.Ordinal);
    readonly ToolTip hints = new() { AutoPopDelay = 15000, InitialDelay = 450, ReshowDelay = 150 };
    readonly Label pageTitle = AppTheme.Label("Обзор", 20);
    readonly Label stateBadge = AppTheme.Label("P · Пауза", 20, true);
    readonly Panel stateDot = new() { Dock = DockStyle.Fill, Margin = Padding.Empty };
    readonly Label connectionSummary = AppTheme.Label("", 9.5f, false, AppTheme.Muted);
    readonly Label exclusionCount = AppTheme.Label("", 10, true);
    readonly Label unsavedChanges = AppTheme.Label("Есть несохранённые изменения", 9.5f, false, AppTheme.Amber);
    readonly Label exclusionPath = AppTheme.Label("Выберите исключение, чтобы увидеть подробности.", 9, false, AppTheme.Muted);
    readonly Panel pageHost = new() { Dock = DockStyle.Fill, Margin = Padding.Empty };
    readonly Button exitApplication = new ThemeButton() { Text = "Выход" };
    TableLayoutPanel shell = null!, contentLayout = null!, overviewLayout = null!;
    Panel sidebar = null!, actionCards = null!;
    FlowLayoutPanel footer = null!;
    Button openSettings = null!;
    internal string CurrentPage { get; private set; } = "overview";
    internal bool IsCompact
    { get; private set; }

    void BuildLayout(bool compact)
    {
        SuspendLayout();
        AutoScaleMode = AutoScaleMode.Dpi;
        AutoScaleDimensions = new SizeF(96, 96);
        BackColor = AppTheme.Background;
        ForeColor = AppTheme.Text;
        Font = new Font("Segoe UI", 10.5f);
        Name = "ProxyBridgeMainForm";
        AccessibleName = "ProxyBridge — управление подключением";
        HandleCreated += (_, _) => AppTheme.TryDarkTitleBar(this);
        SystemColorsChanged += (_, _) => AppTheme.TryDarkTitleBar(this);
        if (IsHandleCreated)
        {
            AppTheme.TryDarkTitleBar(this);
        }

        KeyPreview = true;
        KeyDown += (_, e) => { if (e.KeyCode == Keys.F1) { NavigateTo("help"); e.Handled = true; } };
        shell = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = Padding.Empty };
        shell.ColumnStyles.Add(new(SizeType.Absolute, 208));
        shell.ColumnStyles.Add(new(SizeType.Percent, 100));
        shell.RowStyles.Add(new(SizeType.Percent, 100));
        sidebar = BuildSidebar();
        shell.Controls.Add(sidebar, 0, 0);
        contentLayout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(24), ColumnCount = 1, RowCount = 4, Margin = Padding.Empty };
        contentLayout.ColumnStyles.Add(new(SizeType.Percent, 100));
        contentLayout.RowStyles.Add(new(SizeType.Absolute, 64));
        contentLayout.RowStyles.Add(new(SizeType.Absolute, 140));
        contentLayout.RowStyles.Add(new(SizeType.Percent, 100));
        contentLayout.RowStyles.Add(new(SizeType.Absolute, 58));
        contentLayout.Controls.Add(BuildHeader(), 0, 0);
        contentLayout.Controls.Add(BuildStatusCard(), 0, 1);
        pageHost.Padding = new Padding(0, 16, 0, 0);
        contentLayout.Controls.Add(pageHost, 0, 2);
        footer = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(0, 12, 0, 0), Margin = Padding.Empty };
        StyleAction(apply, "apply", 224, primary: true);
        unsavedChanges.Name = "unsavedChanges";
        unsavedChanges.AccessibleName = "Есть несохранённые изменения";
        unsavedChanges.Dock = DockStyle.None;
        unsavedChanges.Size = new Size(290, 40);
        unsavedChanges.TextAlign = ContentAlignment.MiddleRight;
        unsavedChanges.Margin = new Padding(0, 0, 12, 0);
        footer.Controls.AddRange([apply, unsavedChanges]);
        contentLayout.Controls.Add(footer, 0, 3);
        shell.Controls.Add(contentLayout, 1, 0);
        Controls.Add(shell);
        pages.Add("overview", BuildOverview());
        pages.Add("proxy", BuildProxyPage());
        pages.Add("exclusions", BuildExclusionsPage());
        pages.Add("help", BuildHelpPage());
        foreach (var page in pages.Values)
        {
            page.Dock = DockStyle.Fill;
            page.Visible = false;
            pageHost.Controls.Add(page);
        }
        hints.SetToolTip(apply, "Сохранить поля прокси и список исключений. При подключении настройки применятся с переподключением.");
        foreach (var input in new[] { host, port, username, password })
        {
            input.TextChanged += (_, _) => RefreshOverviewSummary();
        }

        protocol.SelectedIndexChanged += (_, _) => RefreshOverviewSummary();
        SetCompactLayout(compact);
        NavigateTo("overview");
        RefreshLayoutStatus();
        ResumeLayout(true);
    }

    Panel BuildSidebar()
    {
        var panel = new ThemeCard
        {
            CornerRadius = 24,
            Dock = DockStyle.Fill,
            BackColor = AppTheme.Sidebar,
            Padding = new Padding(12, 20, 12, 16),
            Margin = new Padding(12, 12, 0, 12)
        };
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 8, Margin = Padding.Empty };
        layout.ColumnStyles.Add(new(SizeType.Percent, 100));
        layout.RowStyles.Add(new(SizeType.Absolute, 40));
        layout.RowStyles.Add(new(SizeType.Absolute, 56));
        for (int i = 0; i < 4; i++)
        {
            layout.RowStyles.Add(new(SizeType.Absolute, 52));
        }

        layout.RowStyles.Add(new(SizeType.Percent, 100));
        layout.RowStyles.Add(new(SizeType.Absolute, 90));
        layout.Controls.Add(AppTheme.Label("ProxyBridge", 16, true), 0, 0);
        layout.Controls.Add(AppTheme.Label("Ваше подключение\nпод контролем", 9.5f, false, AppTheme.Muted), 0, 1);
        var entries = new[] { ("overview", "Обзор", "navOverview"), ("proxy", "Прокси", "navProxy"), ("exclusions", "Исключения", "navExclusions"), ("help", "Справка", "navHelp") };
        for (int i = 0; i < entries.Length; i++)
        {
            var (key, text, name) = entries[i];
            var button = new ThemeButton { Name = name, Text = text, NavigationIcon = key, Dock = DockStyle.Fill, Margin = new Padding(0, 4, 0, 4), TextAlign = ContentAlignment.MiddleLeft, TabIndex = i };
            AppTheme.Button(button);
            button.Padding = new Padding(14, 0, 0, 0);
            button.FlatAppearance.BorderSize = 0;
            button.Click += (_, _) => NavigateTo(key);
            navigation.Add(key, button);
            layout.Controls.Add(button, 0, i + 2);
        }
        layout.Controls.Add(AppTheme.Label($"ProxyBridge {AppVersion.Display}\nD — подключено · P — пауза\nS — сбой\nF1 — справка", 9, false, AppTheme.Muted), 0, 7);
        panel.Controls.Add(layout);
        return panel;
    }

    Control BuildHeader()
    {
        var header = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = Padding.Empty };
        header.ColumnStyles.Add(new(SizeType.Percent, 100));
        header.ColumnStyles.Add(new(SizeType.AutoSize));
        pageTitle.Name = "pageTitle";
        header.Controls.Add(pageTitle, 0, 0);
        var buttons = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, WrapContents = false, Padding = new Padding(0, 8, 0, 0), Margin = Padding.Empty };
        openSettings = new ThemeButton { Text = "Открыть настройки" };
        StyleAction(openSettings, "openSettings", 180);
        openSettings.Click += (_, _) => NavigateTo("proxy");
        var minimize = new ThemeButton { Text = "В трей" };
        StyleAction(minimize, "minimizeToTray", 88);
        minimize.Click += (_, _) => Hide();
        hints.SetToolTip(minimize, "Скрыть окно. Приложение продолжит работать; открыть его можно из трея.");
        StyleAction(exitApplication, "exitApplication", 88);
        foreach (var utility in new[] { minimize, exitApplication })
        {
            utility.BackColor = AppTheme.Background;
            utility.FlatAppearance.BorderSize = 1;
            utility.ForeColor = AppTheme.Muted;
        }
        hints.SetToolTip(exitApplication, "Закрыть программу, сохранив блокировку");
        buttons.Controls.AddRange([openSettings, minimize, exitApplication]);
        header.Controls.Add(buttons, 1, 0);
        return header;
    }

    Control BuildStatusCard()
    {
        var card = AppTheme.NewCard();
        card.Name = "connectionCard";
        card.Padding = new Padding(24, 16, 24, 16);
        var rows = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, Margin = Padding.Empty };
        rows.ColumnStyles.Add(new(SizeType.Percent, 100));
        rows.RowStyles.Add(new(SizeType.Absolute, 38));
        rows.RowStyles.Add(new(SizeType.Percent, 100));
        rows.RowStyles.Add(new(SizeType.Absolute, 24));
        var stateLine = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = Padding.Empty };
        stateLine.ColumnStyles.Add(new(SizeType.Percent, 100));
        stateLine.ColumnStyles.Add(new(SizeType.Absolute, 20));
        stateLine.RowStyles.Add(new(SizeType.Percent, 100));
        stateDot.Paint += (_, e) =>
        {
            e.Graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            Color dotColor = VisualState == ProxyVisualState.Connected ? AppTheme.Green
                : VisualState == ProxyVisualState.Failed ? AppTheme.Red : AppTheme.Amber;
            using var brush = new SolidBrush(dotColor);
            float size = AppTheme.Scale(stateDot, 8);
            e.Graphics.FillEllipse(brush, (stateDot.Width - size) / 2, (stateDot.Height - size) / 2, size, size);
        };
        stateBadge.Name = "stateBadge";
        stateLine.Controls.Add(stateBadge, 0, 0);
        stateLine.Controls.Add(stateDot, 1, 0);
        rows.Controls.Add(stateLine, 0, 0);
        status.Name = "connectionStatus";
        status.AutoSize = false;
        status.Dock = DockStyle.Fill;
        status.Margin = Padding.Empty;
        status.Font = new Font("Segoe UI", 11);
        status.TextAlign = ContentAlignment.MiddleLeft;
        status.AccessibleName = "Текущее состояние подключения";
        rows.Controls.Add(status, 0, 1);
        connectionSummary.Name = "connectionSummary";
        rows.Controls.Add(connectionSummary, 0, 2);
        card.Controls.Add(rows);
        return card;
    }

    Control BuildOverview()
    {
        overviewLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 5, Margin = Padding.Empty };
        overviewLayout.ColumnStyles.Add(new(SizeType.Percent, 100));
        overviewLayout.RowStyles.Add(new(SizeType.Absolute, 112));
        overviewLayout.RowStyles.Add(new(SizeType.Absolute, 48));
        overviewLayout.RowStyles.Add(new(SizeType.Percent, 100));
        userLogNote.Font = Font;
        int noteHeight = userLogNote.Font.Height * 3 + SystemInformation.BorderSize.Height * 2 + 4;
        overviewLayout.RowStyles.Add(new(SizeType.Absolute, noteHeight + 8));
        overviewLayout.RowStyles.Add(new(SizeType.Absolute, 52));
        actionCards = new Panel { Dock = DockStyle.Fill, Margin = Padding.Empty };
        var actions = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 1, Margin = Padding.Empty };
        for (int i = 0; i < 3; i++)
        {
            actions.ColumnStyles.Add(new(SizeType.Percent, 100f / 3));
        }

        var commands = new[] { (connect, "connect", "Проверить прокси и подключиться"), (block, "block", "Оставить блокировку"), (release, "release", "Снять блокировку для всех приложений") };
        for (int i = 0; i < commands.Length; i++)
        {
            var (button, name, caption) = commands[i];
            var card = new Panel
            {
                Dock = DockStyle.Fill,
                Padding = Padding.Empty,
                Margin = new Padding(i == 0 ? 0 : 6, 0, i == 2 ? 0 : 6, 8)
            };
            var grid = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Margin = Padding.Empty };
            grid.RowStyles.Add(new(SizeType.Absolute, 60));
            grid.RowStyles.Add(new(SizeType.Percent, 100));
            StyleAction(button, name, 180, primary: i == 0);
            ((ThemeButton)button).CornerRadius = 22;
            if (i == 2)
            {
                button.BackColor = AppTheme.Background;
                button.ForeColor = AppTheme.Text;
            }
            if (i == 1)
            {
                button.Text = "Остановить и\nблокировать";
            }

            if (i == 2)
            {
                button.Text = "Отключить и\nвернуть интернет";
            }

            button.Dock = DockStyle.Fill;
            button.Margin = Padding.Empty;
            button.TabIndex = i;
            grid.Controls.Add(button, 0, 0);
            grid.Controls.Add(AppTheme.Label(caption, 9.25f, false, AppTheme.Muted), 0, 1);
            card.Controls.Add(grid);
            actions.Controls.Add(card, i, 0);
        }
        actionCards.Controls.Add(actions);
        overviewLayout.Controls.Add(actionCards, 0, 0);
        hints.SetToolTip(connect, "Подключиться с сохранением защиты остальных приложений. Результат проверки появится в журнале.");
        hints.SetToolTip(block, "Остановить прокси и сохранить блокировку. Приложения и адреса из исключений остаются разрешены.");
        hints.SetToolTip(release, "Явно снять защиту ProxyBridge и вернуть обычный доступ в интернет.");
        var journalHeader = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false, Margin = Padding.Empty };
        var journalTitle = AppTheme.Label("Журнал событий", 11, true);
        journalTitle.Dock = DockStyle.None;
        journalTitle.Size = new Size(166, 40);
        StyleAction(speed, "speed", 144);
        StyleAction(cancelSpeed, "cancelSpeed", 144);
        cancelSpeed.Visible = cancelSpeed.Enabled;
        cancelSpeed.EnabledChanged += (_, _) => cancelSpeed.Visible = cancelSpeed.Enabled;
        speed.TabIndex = 3;
        cancelSpeed.TabIndex = 4;
        journalHeader.Controls.AddRange([journalTitle, speed, cancelSpeed]);
        overviewLayout.Controls.Add(journalHeader, 0, 1);
        hints.SetToolTip(speed, "Проверить HTTPS-задержку и скорость загрузки через подключённый прокси. Результаты появятся в журнале.");
        var journalCard = AppTheme.NewCard();
        journalCard.Padding = new Padding(12);
        log.Name = "startupLog";
        log.BackColor = AppTheme.Input;
        log.ForeColor = AppTheme.Text;
        log.BorderStyle = BorderStyle.None;
        log.Font = new Font("Consolas", 9.5f);
        log.Margin = Padding.Empty;
        log.TabIndex = 5;
        log.AccessibleName = "Журнал запуска и подключения";
        log.AccessibleDescription = "Результаты реальных операций, проверок и теста скорости. Только чтение.";
        journalCard.BackColor = AppTheme.Input;
        journalCard.Controls.Add(log);
        overviewLayout.Controls.Add(journalCard, 0, 2);
        var noteRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = Padding.Empty, Padding = new Padding(0, 8, 0, 0) };
        noteRow.ColumnStyles.Add(new(SizeType.Percent, 100));
        noteRow.ColumnStyles.Add(new(SizeType.Absolute, 152));
        noteRow.RowStyles.Add(new(SizeType.Percent, 100));
        userLogNote.Name = "userLogNote";
        userLogNote.Dock = DockStyle.Fill;
        userLogNote.Margin = Padding.Empty;
        userLogNote.PlaceholderText = "Заметка к журналу: что вы делали перед сбоем…";
        userLogNote.BackColor = AppTheme.Input;
        userLogNote.ForeColor = AppTheme.Text;
        userLogNote.BorderStyle = BorderStyle.None;
        userLogNote.TabIndex = 6;
        userLogNote.AccessibleName = "Заметка пользователя для журнала";
        userLogNote.AccessibleDescription = "Три строки с прокруткой. Enter добавляет строку; запись выполняется кнопкой «Записать в лог».";
        StyleAction(writeLogNote, "writeLogNote", 152);
        writeLogNote.Margin = Padding.Empty;
        writeLogNote.Anchor = AnchorStyles.Left | AnchorStyles.Right;
        writeLogNote.TabIndex = 7;
        hints.SetToolTip(userLogNote, "Опишите своё действие и нажмите «Записать в лог». Enter добавляет новую строку.");
        var noteCard = AppTheme.NewCard();
        noteCard.CornerRadius = 12;
        noteCard.BackColor = AppTheme.Input;
        noteCard.Padding = new Padding(8, 4, 8, 4);
        noteCard.Margin = new Padding(0, 0, 8, 0);
        noteCard.Controls.Add(userLogNote);
        noteRow.Controls.Add(noteCard, 0, 0);
        noteRow.Controls.Add(writeLogNote, 1, 0);
        overviewLayout.Controls.Add(noteRow, 0, 3);
        var activityRow = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 2,
            Margin = Padding.Empty,
            Padding = new Padding(0, 6, 0, 0)
        };
        activityRow.ColumnStyles.Add(new(SizeType.Percent, 100));
        activityRow.ColumnStyles.Add(new(SizeType.Absolute, 152));
        activityRow.RowStyles.Add(new(SizeType.Percent, 55));
        activityRow.RowStyles.Add(new(SizeType.Percent, 45));
        activityLogging.Name = "activityLogging";
        activityLogging.AccessibleName = "Журнал активности программ";
        activityLogging.ForeColor = AppTheme.Text;
        activityLogging.Margin = Padding.Empty;
        activityLogging.Anchor = AnchorStyles.Left;
        activityLogging.TabIndex = 8;
        // Native disabled CheckBox text is nearly black on the dark background.
        // Keep its real enabled state and render the caption with the theme.
        var activityCaption = new Label
        {
            Text = "Журнал активности программ",
            Name = "activityLoggingCaption",
            AutoSize = false,
            AutoEllipsis = true,
            Dock = DockStyle.Fill,
            Margin = Padding.Empty,
            TextAlign = ContentAlignment.MiddleLeft,
            ForeColor = AppTheme.Text
        };
        var activityToggle = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = Padding.Empty };
        activityToggle.ColumnStyles.Add(new(SizeType.Absolute, 22));
        activityToggle.ColumnStyles.Add(new(SizeType.Percent, 100));
        activityToggle.RowStyles.Add(new(SizeType.Percent, 100));
        activityToggle.Controls.Add(activityLogging, 0, 0);
        activityToggle.Controls.Add(activityCaption, 1, 0);
        activityLogging.EnabledChanged += (_, _) => activityCaption.ForeColor = activityLogging.Enabled ? AppTheme.Text : AppTheme.Muted;
        activityCaption.Click += (_, _) =>
        {
            if (activityLogging.Enabled && !observeOnly && !OperationsClosed)
            {
                activityLogging.Checked = !activityLogging.Checked;
            }
        };
        activityStatus.Name = "activityStatus";
        activityStatus.AccessibleName = "Состояние журнала активности";
        activityStatus.Font = new Font(Font.FontFamily, 8.5f);
        activityStatus.Dock = DockStyle.Fill;
        activityStatus.Margin = Padding.Empty;
        activityStatus.TextAlign = ContentAlignment.MiddleLeft;
        StyleAction(openActivityLog, "openActivityLog", 152);
        openActivityLog.Margin = Padding.Empty;
        openActivityLog.Anchor = AnchorStyles.Left | AnchorStyles.Right;
        openActivityLog.TabIndex = 9;
        activityRow.Controls.Add(activityToggle, 0, 0);
        activityRow.Controls.Add(activityStatus, 0, 1);
        activityRow.Controls.Add(openActivityLog, 1, 0);
        activityRow.SetRowSpan(openActivityLog, 2);
        hints.SetToolTip(activityLogging, "Сохранять активность программ в отдельный файл. Переключение не меняет подключение. Крестик скрывает окно в трей и сохраняет запись; явный выход её останавливает.");
        hints.SetToolTip(activityCaption, hints.GetToolTip(activityLogging));
        hints.SetToolTip(openActivityLog, "Открыть отдельный журнал процессов и сетевых подключений.");
        overviewLayout.Controls.Add(activityRow, 0, 4);
        return overviewLayout;
    }

    Control BuildProxyPage()
    {
        var scroll = new Panel { AutoScroll = true, Dock = DockStyle.Fill, Margin = Padding.Empty };
        var card = AppTheme.NewCard();
        card.Dock = DockStyle.Top;
        card.Height = 390;
        card.Padding = new Padding(20);
        var rows = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 7, Margin = Padding.Empty };
        rows.ColumnStyles.Add(new(SizeType.Absolute, 136));
        rows.ColumnStyles.Add(new(SizeType.Percent, 100));
        var description = AppTheme.Label("Адрес и учётные данные вашего прокси", 11, true);
        rows.Controls.Add(description, 0, 0);
        rows.SetColumnSpan(description, 2);
        rows.RowStyles.Add(new(SizeType.Absolute, 36));
        var inputs = new (string Caption, string Name, Control Control)[] {
            ("IPv4-адрес", "host", host), ("Порт", "port", port), ("Логин", "username", username),
            ("Пароль", "password", password), ("Протокол", "protocol", protocol)
        };
        for (int i = 0; i < inputs.Length; i++)
        {
            var (caption, name, input) = inputs[i];
            var label = AppTheme.Label(caption, 10, false, AppTheme.Muted);
            label.TabIndex = i * 2;
            rows.Controls.Add(label, 0, i + 1);
            input.Name = name;
            input.AccessibleName = caption;
            input.TabIndex = i * 2 + 1;
            input.BackColor = AppTheme.Input;
            input.ForeColor = AppTheme.Text;
            if (input is TextBox text)
            {
                text.BorderStyle = BorderStyle.None;
            }

            if (input is ComboBox combo)
            {
                combo.FlatStyle = FlatStyle.Flat;
                combo.DrawMode = DrawMode.OwnerDrawFixed;
                combo.ItemHeight = Math.Max(18, TextRenderer.MeasureText("Ag", combo.Font, Size.Empty, TextFormatFlags.NoPadding).Height);
                combo.DrawItem += (_, e) =>
                {
                    if (e.Index < 0)
                    {
                        return;
                    }

                    bool selected = (e.State & DrawItemState.Selected) != 0 && (e.State & DrawItemState.ComboBoxEdit) == 0;
                    using var brush = new SolidBrush(selected ? AppTheme.Selection : AppTheme.Input);
                    e.Graphics.FillRectangle(brush, e.Bounds);
                    Color textColor = SystemInformation.HighContrast && selected ? SystemColors.HighlightText : AppTheme.Text;
                    TextRenderer.DrawText(e.Graphics, combo.GetItemText(combo.Items[e.Index]), combo.Font,
                        Rectangle.Inflate(e.Bounds, -3, 0), textColor, TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix);
                    if ((e.State & DrawItemState.Focus) != 0)
                    {
                        e.DrawFocusRectangle();
                    }
                };
            }
            var wrapper = new ThemeCard { CornerRadius = 10, BackColor = AppTheme.Input, Dock = DockStyle.Fill, Padding = new Padding(10, 7, 10, 5), Margin = new Padding(0, 5, 0, 5), TabIndex = i };
            input.Dock = DockStyle.Top;
            wrapper.Controls.Add(input);
            rows.Controls.Add(wrapper, 1, i + 1);
            rows.RowStyles.Add(new(SizeType.Absolute, 46));
        }
        autoStart.Name = "autoStart";
        autoStart.ForeColor = AppTheme.Text;
        autoStart.TabIndex = 11;
        autoStart.AccessibleName = autoStart.Text;
        autoStart.Dock = DockStyle.Top;
        autoStart.Margin = new Padding(0, 14, 0, 0);
        var startupPanel = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Margin = Padding.Empty };
        startupPanel.RowStyles.Add(new(SizeType.Absolute, 38));
        startupPanel.RowStyles.Add(new(SizeType.Percent, 100));
        startupPanel.Controls.Add(autoStart, 0, 0);
        startupPanel.Controls.Add(AppTheme.Label("При входе в Windows откроется журнал проверки. Окно останется на экране.", 9, false, AppTheme.Muted), 0, 1);
        rows.Controls.Add(startupPanel, 0, 6);
        rows.SetColumnSpan(startupPanel, 2);
        rows.RowStyles.Add(new(SizeType.Percent, 100));
        hints.SetToolTip(password, "Пароль скрыт и не выводится в журнал.");
        hints.SetToolTip(autoStart, "Эта настройка применяется сразу. Остальные поля — кнопкой «Сохранить / применить».");
        card.Controls.Add(rows);
        scroll.Controls.Add(card);
        return scroll;
    }

    Control BuildExclusionsPage()
    {
        var rows = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 5, Margin = Padding.Empty };
        rows.ColumnStyles.Add(new(SizeType.Percent, 100));
        rows.RowStyles.Add(new(SizeType.Absolute, 90));
        rows.RowStyles.Add(new(SizeType.Absolute, 30));
        rows.RowStyles.Add(new(SizeType.Percent, 100));
        rows.RowStyles.Add(new(SizeType.Absolute, 34));
        rows.RowStyles.Add(new(SizeType.Absolute, 48));
        rows.Controls.Add(AppTheme.Label("Приложения и адреса из списка доступны напрямую, даже при остановке прокси.\nПри подключении DNS остаётся через прокси; порт 53 не исключается.\nПосле изменения списка нажмите «Сохранить / применить».", 9.5f, false, AppTheme.Muted), 0, 0);
        exclusionCount.Name = "exclusionCount";
        rows.Controls.Add(exclusionCount, 0, 1);
        exclusions.Name = "exclusions";
        exclusions.BackColor = AppTheme.Input;
        exclusions.ForeColor = AppTheme.Text;
        exclusions.BorderStyle = BorderStyle.None;
        exclusions.DrawMode = DrawMode.OwnerDrawFixed;
        exclusions.ItemHeight = 56;
        exclusions.IntegralHeight = false;
        exclusions.HorizontalScrollbar = false;
        exclusions.AccessibleName = "Приложения и адреса с прямым доступом";
        exclusions.TabIndex = 0;
        exclusions.DrawItem += DrawExcludedApplication;
        exclusions.SelectedIndexChanged += (_, _) =>
        {
            string path = exclusions.SelectedItem as string ?? "Выберите исключение, чтобы увидеть подробности.";
            exclusionPath.Text = path;
            hints.SetToolTip(exclusionPath, path);
            hints.SetToolTip(exclusions, path);
        };
        var listSurface = AppTheme.NewCard();
        listSurface.BackColor = AppTheme.Input;
        listSurface.Padding = new Padding(8);
        listSurface.Controls.Add(exclusions);
        rows.Controls.Add(listSurface, 0, 2);
        exclusionPath.Name = "exclusionPath";
        exclusionPath.AutoEllipsis = true;
        rows.Controls.Add(exclusionPath, 0, 3);
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false, Margin = Padding.Empty, Padding = new Padding(0, 6, 0, 0) };
        StyleAction(addExclusion, "addExclusion", 170);
        StyleAction(addAddressExclusion, "addAddressExclusion", 176);
        StyleAction(removeExclusion, "removeExclusion", 108);
        addExclusion.TabIndex = 1;
        addAddressExclusion.TabIndex = 2;
        removeExclusion.TabIndex = 3;
        buttons.Controls.AddRange([addExclusion, addAddressExclusion, removeExclusion]);
        rows.Controls.Add(buttons, 0, 4);
        hints.SetToolTip(addExclusion, "Выберите EXE. Для программы с отдельными вспомогательными процессами могут понадобиться дополнительные EXE.");
        hints.SetToolTip(addAddressExclusion, "Добавить IP-адрес или подсеть, например 192.168.1.0/24. Порт можно указать отдельно.");
        hints.SetToolTip(removeExclusion, "Удалить выбранное исключение из списка. Затем нажмите «Сохранить / применить».");
        return rows;
    }

    void DrawExcludedApplication(object? sender, DrawItemEventArgs e)
    {
        if (e.Index < 0)
        {
            return;
        }

        bool selected = (e.State & DrawItemState.Selected) != 0;
        using var background = new SolidBrush(selected ? AppTheme.Selection : AppTheme.Input);
        e.Graphics.FillRectangle(background, e.Bounds);
        string path = (string)exclusions.Items[e.Index];
        bool isAddress = AddressExclusion.TryParse(path, out var address);
        var title = new Rectangle(e.Bounds.X + 12, e.Bounds.Y + 7, e.Bounds.Width - 24, 22);
        var detail = new Rectangle(e.Bounds.X + 12, e.Bounds.Y + 31, e.Bounds.Width - 24, 19);
        Color titleColor = SystemInformation.HighContrast && selected ? SystemColors.HighlightText : AppTheme.Text;
        Color detailColor = SystemInformation.HighContrast && selected ? SystemColors.HighlightText : AppTheme.Muted;
        string titleText = isAddress ? path : Path.GetFileName(path);
        string detailText = isAddress
            ? address!.Port is int port ? $"Адрес / подсеть · TCP и UDP · порт {port}" : "Адрес / подсеть · TCP и UDP · все порты, кроме DNS (53)"
            : path;
        TextRenderer.DrawText(e.Graphics, titleText, Font, title, titleColor, TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);
        TextRenderer.DrawText(e.Graphics, detailText, exclusionPath.Font, detail, detailColor, TextFormatFlags.PathEllipsis | TextFormatFlags.NoPrefix);
        if ((e.State & DrawItemState.Focus) != 0)
        {
            e.DrawFocusRectangle();
        }
    }

    Control BuildHelpPage()
    {
        var card = AppTheme.NewCard();
        card.Padding = new Padding(12);
        var grid = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = Padding.Empty };
        grid.ColumnStyles.Add(new(SizeType.Absolute, 190));
        grid.ColumnStyles.Add(new(SizeType.Percent, 100));
        var topics = new ListBox { Name = "helpTopics", Dock = DockStyle.Fill, BackColor = AppTheme.Card, ForeColor = AppTheme.Text, BorderStyle = BorderStyle.None, IntegralHeight = false, ItemHeight = 31, DrawMode = DrawMode.OwnerDrawFixed, Margin = new Padding(0, 0, 14, 0), TabIndex = 0, AccessibleName = "Разделы справки" };
        var body = new RichTextBox { Name = "helpBody", Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None, BackColor = AppTheme.Card, ForeColor = AppTheme.Text, Font = new Font("Segoe UI", 10.5f), DetectUrls = false, ScrollBars = RichTextBoxScrollBars.Vertical, TabIndex = 1, AccessibleName = "Содержание справки" };
        foreach (var section in HelpContent.Sections)
        {
            topics.Items.Add(section.Title switch
            {
                "Подключение и остановка" => "Подключение",
                "Исключения приложений" => "Исключения",
                "Если что-то не работает" => "Если есть ошибка",
                "Восстановление интернета" => "Вернуть интернет",
                _ => section.Title
            });
        }

        topics.DrawItem += (_, e) =>
        {
            if (e.Index < 0)
            {
                return;
            }

            bool selected = (e.State & DrawItemState.Selected) != 0;
            using var brush = new SolidBrush(selected ? AppTheme.Selection : AppTheme.Card);
            e.Graphics.FillRectangle(brush, e.Bounds);
            var rect = Rectangle.Inflate(e.Bounds, -7, 0);
            Color textColor = SystemInformation.HighContrast && selected ? SystemColors.HighlightText : AppTheme.Text;
            TextRenderer.DrawText(e.Graphics, (string)topics.Items[e.Index], Font, rect, textColor, TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
            e.DrawFocusRectangle();
        };
        topics.SelectedIndexChanged += (_, _) =>
        {
            if (topics.SelectedIndex < 0)
            {
                return;
            }

            var section = HelpContent.Sections[topics.SelectedIndex];
            body.Text = section.Title + Environment.NewLine + Environment.NewLine + section.Body;
            using var headingFont = new Font("Segoe UI", 15, FontStyle.Bold);
            body.Select(0, section.Title.Length);
            body.SelectionFont = headingFont;
            body.Select(0, 0);
            body.ScrollToCaret();
        };
        grid.Controls.Add(topics, 0, 0);
        grid.Controls.Add(body, 1, 0);
        card.Controls.Add(grid);
        if (topics.Items.Count > 0)
        {
            topics.SelectedIndex = 0;
        }

        return card;
    }

    void StyleAction(Button button, string name, int width, bool primary = false, Color? border = null)
    {
        button.Name = name;
        button.Width = width;
        button.Margin = new Padding(0, 0, 8, 0);
        AppTheme.Button(button, primary, border);
    }
    internal void NavigateTo(string page)
    {
        if (!pages.ContainsKey(page))
        {
            throw new ArgumentOutOfRangeException(nameof(page));
        }

        if (page != "overview" && IsCompact)
        {
            SetCompactLayout(false);
        }

        CurrentPage = page;
        foreach (var entry in pages)
        {
            entry.Value.Visible = entry.Key == page;
        }

        pages[page].BringToFront();
        foreach (var entry in navigation)
        {
            bool active = entry.Key == page;
            ((ThemeButton)entry.Value).Selected = active;
            entry.Value.BackColor = active ? AppTheme.Selection : AppTheme.Sidebar;
            entry.Value.ForeColor = active ? AppTheme.Accent : AppTheme.Muted;
            entry.Value.FlatAppearance.BorderColor = entry.Value.BackColor;
            entry.Value.FlatAppearance.MouseOverBackColor = active ? AppTheme.SelectionHover : AppTheme.Raised;
            entry.Value.FlatAppearance.MouseDownBackColor = AppTheme.Selection;
            entry.Value.AccessibleDescription = active ? "Текущий раздел" : "Открыть раздел";
        }
        pageTitle.Text = IsCompact ? "Запуск ProxyBridge" : navigation[page].Text;
        bool editablePage = page is "proxy" or "exclusions";
        footer.Visible = editablePage;
        contentLayout.RowStyles[3].Height = editablePage ? 58 : 0;
        RefreshOverviewSummary();
    }
    void SetCompactLayout(bool compact)
    {
        IsCompact = compact;
        sidebar.Visible = !compact;
        shell.ColumnStyles[0].Width = compact ? 0 : 208;
        contentLayout.RowStyles[0].Height = compact ? 56 : 64;
        contentLayout.RowStyles[1].Height = 140;
        openSettings.Visible = compact;
        actionCards.Visible = !compact;
        overviewLayout.RowStyles[0].Height = compact ? 0 : 112;
        MinimumSize = compact ? new Size(740, 570) : new Size(900, 706);
        Size = compact ? new Size(780, 610) : new Size(1080, 806);
    }
    void RefreshOverviewSummary()
    {
        connectionSummary.Text = $"Сохранённый прокси: {settings.Host}:{settings.Port}  ·  EXE: {settings.ExcludedApplications.Length} · Адресов: {settings.ExcludedAddresses.Length}";
        exclusionCount.Text = $"В списке: {ExcludedApplicationItems().Length} EXE · Адресов и подсетей: {ExcludedAddressItems().Length}";
        bool changed = host.Text.Trim() != settings.Host ||
            !int.TryParse(port.Text, out int enteredPort) || enteredPort != settings.Port ||
            username.Text != settings.Username || password.Text != settings.Password ||
            protocol.SelectedIndex != (settings.Protocol == "http" ? 0 : 1) ||
            !ExcludedApplicationItems().SequenceEqual(settings.ExcludedApplications, StringComparer.OrdinalIgnoreCase) ||
            !ExcludedAddressItems().SequenceEqual(settings.ExcludedAddresses, StringComparer.Ordinal);
        unsavedChanges.Visible = changed;
    }
    void RefreshLayoutStatus()
    {
        stateBadge.Text = VisualState switch
        {
            ProxyVisualState.Connected => "D · Подключено",
            ProxyVisualState.Failed => "S · Сбой",
            ProxyVisualState.Connecting => "P · Подключение",
            _ => "P · Пауза"
        };
        stateBadge.ForeColor = AppTheme.Text;
        status.ForeColor = AppTheme.Text;
        stateDot.Invalidate();
        RefreshOverviewSummary();
    }
}
