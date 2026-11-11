namespace ProxyBridge;

internal sealed partial class MainForm
{
    readonly Dictionary<string, Control> pages = new(StringComparer.Ordinal);
    readonly Dictionary<string, Button> navigation = new(StringComparer.Ordinal);
    readonly ToolTip hints = new() { AutoPopDelay = 15000, InitialDelay = 450, ReshowDelay = 150 };
    // Type scale (Apple-style roles): page 18, status 15, section 11 Semibold,
    // body 10, caption 9 Muted, journal 9.5 monospace.
    readonly Label pageTitle = AppTheme.Label("Обзор", 18, true);
    readonly Label stateBadge = AppTheme.Label("P · Пауза", 15, true);
    readonly Panel stateDot = new() { Dock = DockStyle.Fill, Margin = Padding.Empty };
    readonly Label connectionSummary = AppTheme.Label("", 9, false, AppTheme.Muted);
    readonly Label inlineSummary = AppTheme.Label("", 9, false, AppTheme.Muted);
    readonly Label exclusionCount = AppTheme.Label("", 10, true);
    readonly Label unsavedChanges = AppTheme.Label("Есть несохранённые изменения", 9, false, AppTheme.Amber);
    readonly Label exclusionPath = AppTheme.Label("Выберите исключение, чтобы увидеть подробности.", 9, false, AppTheme.Muted);
    readonly Panel pageHost = new() { Dock = DockStyle.Fill, Margin = Padding.Empty };
    readonly Button exitApplication = new ThemeButton() { Text = "Выход" };
    readonly Font stateFontFull = AppTheme.Font(15, true), stateFontSlim = AppTheme.Font(11, true);
    TableLayoutPanel shell = null!, contentLayout = null!, overviewLayout = null!, statusRows = null!, stateLine = null!;
    ThemeCard statusCard = null!;
    readonly Font navigationFont = AppTheme.Font(10), navigationFontSelected = AppTheme.Font(10, true);
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
        Font = AppTheme.Font(10);
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
        contentLayout.RowStyles.Add(new(SizeType.Absolute, FullStatusHeight));
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
        unsavedChanges.Size = new Size(290, 32);
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
        // Flat full-height sidebar separated by one hairline, as in System Settings.
        var panel = new ThemeCard
        {
            CornerRadius = 0,
            BorderMode = ThemeCardBorder.Right,
            Dock = DockStyle.Fill,
            BackColor = AppTheme.Sidebar,
            Padding = new Padding(10, 20, 11, 16),
            Margin = Padding.Empty
        };
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 8, Margin = Padding.Empty };
        layout.ColumnStyles.Add(new(SizeType.Percent, 100));
        layout.RowStyles.Add(new(SizeType.Absolute, 30));
        layout.RowStyles.Add(new(SizeType.Absolute, 52));
        for (int i = 0; i < 4; i++)
        {
            layout.RowStyles.Add(new(SizeType.Absolute, 40));
        }

        layout.RowStyles.Add(new(SizeType.Percent, 100));
        layout.RowStyles.Add(new(SizeType.Absolute, 44));
        var appName = AppTheme.Label("ProxyBridge", 13, true);
        appName.Padding = new Padding(4, 0, 0, 0);
        layout.Controls.Add(appName, 0, 0);
        var tagline = AppTheme.Label("Ваше подключение\nпод контролем", 9, false, AppTheme.Muted);
        tagline.Padding = new Padding(4, 0, 0, 8);
        tagline.TextAlign = ContentAlignment.TopLeft;
        layout.Controls.Add(tagline, 0, 1);
        var entries = new[] { ("overview", "Обзор", "navOverview"), ("proxy", "Прокси", "navProxy"), ("exclusions", "Исключения", "navExclusions"), ("help", "Справка", "navHelp") };
        for (int i = 0; i < entries.Length; i++)
        {
            var (key, text, name) = entries[i];
            var button = new ThemeButton { Name = name, Text = text, NavigationIcon = key, Dock = DockStyle.Fill, Margin = new Padding(0, 2, 0, 2), TextAlign = ContentAlignment.MiddleLeft, TabIndex = i };
            AppTheme.Button(button);
            button.Padding = new Padding(8, 0, 0, 0);
            button.FlatAppearance.BorderSize = 0;
            button.Click += (_, _) => NavigateTo(key);
            navigation.Add(key, button);
            layout.Controls.Add(button, 0, i + 2);
        }
        var versionLabel = AppTheme.Label($"ProxyBridge {AppVersion.Display}\nF1 — справка", 9, false, AppTheme.Muted);
        versionLabel.Padding = new Padding(4, 0, 0, 0);
        versionLabel.TextAlign = ContentAlignment.BottomLeft;
        hints.SetToolTip(versionLabel, "Значок в трее: D — подключено, P — пауза или подключение, S — сбой.");
        layout.Controls.Add(versionLabel, 0, 7);
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
        var buttons = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, WrapContents = false, Padding = new Padding(0, 14, 0, 0), Margin = Padding.Empty };
        openSettings = new ThemeButton { Text = "Открыть настройки" };
        StyleAction(openSettings, "openSettings", 180);
        openSettings.Click += (_, _) => NavigateTo("proxy");
        var minimize = new ThemeButton { Text = "В трей" };
        StyleAction(minimize, "minimizeToTray", 88);
        minimize.Click += (_, _) => Hide();
        hints.SetToolTip(minimize, "Скрыть окно. Приложение продолжит работать; открыть его можно из трея.");
        StyleAction(exitApplication, "exitApplication", 88);
        // Utility commands are quiet: no fill or outline until hovered.
        foreach (var utility in new[] { minimize, exitApplication })
        {
            utility.BackColor = AppTheme.Background;
            utility.FlatAppearance.BorderSize = 0;
            utility.FlatAppearance.MouseOverBackColor = AppTheme.Raised;
            utility.FlatAppearance.MouseDownBackColor = AppTheme.Pressed;
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
        card.Padding = new Padding(20, 14, 20, 14);
        statusCard = card;
        statusRows = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, Margin = Padding.Empty };
        statusRows.ColumnStyles.Add(new(SizeType.Percent, 100));
        statusRows.RowStyles.Add(new(SizeType.Absolute, 32));
        statusRows.RowStyles.Add(new(SizeType.Percent, 100));
        statusRows.RowStyles.Add(new(SizeType.Absolute, 22));
        // Icon (shape + colour) | state | inline summary (slim card only).
        stateLine = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 1, Margin = Padding.Empty };
        stateLine.ColumnStyles.Add(new(SizeType.Absolute, 26));
        stateLine.ColumnStyles.Add(new(SizeType.AutoSize));
        stateLine.ColumnStyles.Add(new(SizeType.Percent, 100));
        stateLine.RowStyles.Add(new(SizeType.Percent, 100));
        stateDot.Name = "stateIcon";
        stateDot.Paint += (_, e) => DrawStateIcon(e.Graphics);
        stateBadge.Name = "stateBadge";
        stateBadge.AutoSize = true;
        stateBadge.Dock = DockStyle.Fill;
        stateLine.Controls.Add(stateDot, 0, 0);
        stateLine.Controls.Add(stateBadge, 1, 0);
        inlineSummary.Name = "connectionSummaryInline";
        inlineSummary.TextAlign = ContentAlignment.MiddleRight;
        inlineSummary.AutoEllipsis = true;
        inlineSummary.Visible = false;
        stateLine.Controls.Add(inlineSummary, 2, 0);
        statusRows.Controls.Add(stateLine, 0, 0);
        status.Name = "connectionStatus";
        status.AutoSize = false;
        status.Dock = DockStyle.Fill;
        status.Margin = Padding.Empty;
        status.Font = AppTheme.Font(10);
        status.TextAlign = ContentAlignment.MiddleLeft;
        status.AccessibleName = "Текущее состояние подключения";
        statusRows.Controls.Add(status, 0, 1);
        connectionSummary.Name = "connectionSummary";
        statusRows.Controls.Add(connectionSummary, 0, 2);
        card.Controls.Add(statusRows);
        return card;
    }

    const int FullStatusHeight = 128, CompactStatusHeight = 140, SlimStatusHeight = 48;

    // The full card on Overview (and in the compact startup view); a single
    // line on the other pages so forms, lists and help get the height.
    void SetStatusCardSlim(bool slim)
    {
        statusCard.Padding = slim ? new Padding(16, 6, 16, 6) : new Padding(20, 14, 20, 14);
        statusRows.RowStyles[0].SizeType = slim ? SizeType.Percent : SizeType.Absolute;
        statusRows.RowStyles[0].Height = slim ? 100 : 32;
        statusRows.RowStyles[1].SizeType = slim ? SizeType.Absolute : SizeType.Percent;
        statusRows.RowStyles[1].Height = slim ? 0 : 100;
        statusRows.RowStyles[2].Height = slim ? 0 : 22;
        status.Visible = connectionSummary.Visible = !slim;
        inlineSummary.Visible = slim;
        stateBadge.Font = slim ? stateFontSlim : stateFontFull;
        contentLayout.RowStyles[1].Height = slim ? SlimStatusHeight : IsCompact ? CompactStatusHeight : FullStatusHeight;
    }

    // Static 16 px state icon: shape plus colour, so the state reads without
    // colour vision. No animation, including while connecting.
    void DrawStateIcon(Graphics graphics)
    {
        graphics.Clear(AppTheme.Card);
        float size = AppTheme.Scale(stateDot, 16);
        var box = new RectangleF(0, (stateDot.Height - size) / 2, size, size);
        var saved = graphics.Save();
        try
        {
            graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            float stroke = Math.Max(1.5f, AppTheme.Scale(stateDot, 2));
            Color color = VisualState switch
            {
                ProxyVisualState.Connected => AppTheme.Green,
                ProxyVisualState.Failed => AppTheme.Red,
                ProxyVisualState.Connecting => AppTheme.Accent,
                _ => AppTheme.Amber
            };
            if (VisualState == ProxyVisualState.Connecting)
            {
                using var ring = new Pen(color, stroke);
                graphics.DrawEllipse(ring, RectangleF.Inflate(box, -stroke / 2, -stroke / 2));
                return;
            }

            using (var fill = new SolidBrush(color))
            {
                graphics.FillEllipse(fill, box);
            }

            using var mark = new Pen(AppTheme.Card, stroke)
            {
                StartCap = System.Drawing.Drawing2D.LineCap.Round,
                EndCap = System.Drawing.Drawing2D.LineCap.Round,
                LineJoin = System.Drawing.Drawing2D.LineJoin.Round
            };
            float x = box.X, y = box.Y, s = box.Width;
            switch (VisualState)
            {
                case ProxyVisualState.Connected:
                    graphics.DrawLines(mark, [new PointF(x + s * .28f, y + s * .52f), new PointF(x + s * .44f, y + s * .68f), new PointF(x + s * .73f, y + s * .36f)]);
                    break;
                case ProxyVisualState.Failed:
                    graphics.DrawLine(mark, x + s / 2, y + s * .27f, x + s / 2, y + s * .56f);
                    using (var dot = new SolidBrush(AppTheme.Card))
                    {
                        float d = stroke * 1.1f;
                        graphics.FillEllipse(dot, x + s / 2 - d / 2, y + s * .72f - d / 2, d, d);
                    }
                    break;
                default:
                    graphics.DrawLine(mark, x + s * .39f, y + s * .32f, x + s * .39f, y + s * .68f);
                    graphics.DrawLine(mark, x + s * .61f, y + s * .32f, x + s * .61f, y + s * .68f);
                    break;
            }
        }
        finally { graphics.Restore(saved); }
    }

    Control BuildOverview()
    {
        overviewLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 5, Margin = Padding.Empty };
        overviewLayout.ColumnStyles.Add(new(SizeType.Percent, 100));
        overviewLayout.RowStyles.Add(new(SizeType.Absolute, 108));
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
            // Two-line captions at 10 pt need 56 px (DesignPreview text-height).
            grid.RowStyles.Add(new(SizeType.Absolute, 56));
            grid.RowStyles.Add(new(SizeType.Percent, 100));
            // One primary action plus two equal secondary actions.
            StyleAction(button, name, 180, primary: i == 0);
            ((ThemeButton)button).CornerRadius = 12;
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
            grid.Controls.Add(AppTheme.Label(caption, 9, false, AppTheme.Muted), 0, 1);
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
        journalTitle.Size = new Size(166, 32);
        journalTitle.Margin = new Padding(0, 8, 0, 0);
        StyleAction(speed, "speed", 144);
        StyleAction(cancelSpeed, "cancelSpeed", 144);
        speed.Margin = cancelSpeed.Margin = new Padding(0, 8, 8, 0);
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
        log.Font = AppTheme.MonoFont(9.5f);
        AppTheme.DarkNative(log);
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
        AppTheme.DarkNative(userLogNote);
        userLogNote.TabIndex = 6;
        userLogNote.AccessibleName = "Заметка пользователя для журнала";
        userLogNote.AccessibleDescription = "Три строки с прокруткой. Enter добавляет строку; запись выполняется кнопкой «Записать в лог».";
        StyleAction(writeLogNote, "writeLogNote", 152);
        writeLogNote.Margin = Padding.Empty;
        writeLogNote.Anchor = AnchorStyles.Left | AnchorStyles.Right;
        writeLogNote.TabIndex = 7;
        hints.SetToolTip(userLogNote, "Опишите своё действие и нажмите «Записать в лог». Enter добавляет новую строку.");
        var noteCard = AppTheme.NewCard();
        noteCard.CornerRadius = 8;
        noteCard.BackColor = AppTheme.Input;
        noteCard.Padding = new Padding(8, 4, 8, 4);
        noteCard.Margin = new Padding(0, 0, 8, 0);
        noteCard.Controls.Add(userLogNote);
        FocusOutline(noteCard, userLogNote);
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
        activityStatus.Font = AppTheme.Font(9);
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
        card.Height = 380;
        card.Padding = new Padding(16);
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
                AppTheme.DarkNative(combo, "DarkMode_CFD");
                combo.DrawMode = DrawMode.OwnerDrawFixed;
                combo.ItemHeight = Math.Max(18, TextRenderer.MeasureText("Ag", combo.Font, Size.Empty, TextFormatFlags.NoPadding).Height);
                combo.DrawItem += (_, e) =>
                {
                    if (e.Index < 0)
                    {
                        return;
                    }

                    bool selected = (e.State & DrawItemState.Selected) != 0 && (e.State & DrawItemState.ComboBoxEdit) == 0;
                    DrawListRow(e.Graphics, e.Bounds, AppTheme.Input, selected, inset: 2);
                    Color textColor = SystemInformation.HighContrast && selected ? SystemColors.HighlightText : AppTheme.Text;
                    TextRenderer.DrawText(e.Graphics, combo.GetItemText(combo.Items[e.Index]), combo.Font,
                        Rectangle.Inflate(e.Bounds, -6, 0), textColor, TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix);
                    if ((e.State & DrawItemState.Focus) != 0 && SystemInformation.HighContrast)
                    {
                        e.DrawFocusRectangle();
                    }
                };
            }
            var wrapper = new ThemeCard { CornerRadius = 8, BackColor = AppTheme.Input, Dock = DockStyle.Fill, Padding = new Padding(10, 6, 10, 4), Margin = new Padding(0, 5, 0, 5), TabIndex = i };
            if (input is ComboBox flat && !SystemInformation.HighContrast)
            {
                // WinForms paints a light frame around a flat ComboBox with system
                // colours. Clip 2 px of it inside a dark host; the rounded wrapper
                // provides the visible outline. Keyboard and accessibility unchanged.
                var clip = new Panel { Dock = DockStyle.Top, Height = Math.Max(1, flat.PreferredHeight - 4), BackColor = AppTheme.Input, Margin = Padding.Empty };
                flat.Location = new Point(-2, -2);
                flat.Anchor = AnchorStyles.Left | AnchorStyles.Top;
                clip.Resize += (_, _) => flat.Width = clip.Width + 4;
                clip.Controls.Add(flat);
                wrapper.Controls.Add(clip);
            }
            else
            {
                input.Dock = DockStyle.Top;
                wrapper.Controls.Add(input);
            }
            FocusOutline(wrapper, input);
            rows.Controls.Add(wrapper, 1, i + 1);
            rows.RowStyles.Add(new(SizeType.Absolute, 44));
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
        rows.RowStyles.Add(new(SizeType.Absolute, 60));
        rows.RowStyles.Add(new(SizeType.Absolute, 30));
        rows.RowStyles.Add(new(SizeType.Percent, 100));
        rows.RowStyles.Add(new(SizeType.Absolute, 34));
        rows.RowStyles.Add(new(SizeType.Absolute, 48));
        rows.Controls.Add(AppTheme.Label("Приложения и адреса из списка доступны напрямую, даже при остановке прокси.\nПри подключении DNS остаётся через прокси; порт 53 не исключается.\nПосле изменения списка нажмите «Сохранить / применить».", 9, false, AppTheme.Muted), 0, 0);
        exclusionCount.Name = "exclusionCount";
        rows.Controls.Add(exclusionCount, 0, 1);
        exclusions.Name = "exclusions";
        exclusions.BackColor = AppTheme.Input;
        exclusions.ForeColor = AppTheme.Text;
        exclusions.BorderStyle = BorderStyle.None;
        exclusions.DrawMode = DrawMode.OwnerDrawFixed;
        exclusions.ItemHeight = 52;
        AppTheme.DarkNative(exclusions);
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
        DrawListRow(e.Graphics, e.Bounds, AppTheme.Input, selected, inset: 4);
        string path = (string)exclusions.Items[e.Index];
        bool isAddress = AddressExclusion.TryParse(path, out var address);
        var title = new Rectangle(e.Bounds.X + 14, e.Bounds.Y + 6, e.Bounds.Width - 28, 22);
        var detail = new Rectangle(e.Bounds.X + 14, e.Bounds.Y + 28, e.Bounds.Width - 28, 19);
        Color titleColor = SystemInformation.HighContrast && selected ? SystemColors.HighlightText : AppTheme.Text;
        Color detailColor = SystemInformation.HighContrast && selected ? SystemColors.HighlightText : AppTheme.Muted;
        string titleText = isAddress ? path : Path.GetFileName(path);
        string detailText = isAddress
            ? address!.Port is int port ? $"Адрес / подсеть · TCP и UDP · порт {port}" : "Адрес / подсеть · TCP и UDP · все порты, кроме DNS (53)"
            : path;
        TextRenderer.DrawText(e.Graphics, titleText, Font, title, titleColor, TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);
        TextRenderer.DrawText(e.Graphics, detailText, exclusionPath.Font, detail, detailColor, TextFormatFlags.PathEllipsis | TextFormatFlags.NoPrefix);
        if ((e.State & DrawItemState.Focus) != 0 && SystemInformation.HighContrast)
        {
            e.DrawFocusRectangle();
        }
    }

    // List rows: rounded selection inset from the list edges; high contrast
    // keeps the plain system highlight rectangle.
    static void DrawListRow(Graphics graphics, Rectangle bounds, Color surface, bool selected, int inset)
    {
        if (SystemInformation.HighContrast)
        {
            using var plain = new SolidBrush(selected ? SystemColors.Highlight : surface);
            graphics.FillRectangle(plain, bounds);
            return;
        }

        using (var brush = new SolidBrush(surface))
        {
            graphics.FillRectangle(brush, bounds);
        }

        if (!selected)
        {
            return;
        }

        var saved = graphics.Save();
        try
        {
            graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            var row = new RectangleF(bounds.X + inset, bounds.Y + 1, bounds.Width - inset * 2, bounds.Height - 2);
            using var path = AppTheme.Rounded(row, 6);
            using var fill = new SolidBrush(AppTheme.Selection);
            graphics.FillPath(fill, path);
        }
        finally { graphics.Restore(saved); }
    }

    // A text field shows focus on its rounded wrapper (2 px Accent), never as
    // a bare caret only. Error states set Emphasis to Red elsewhere.
    static void FocusOutline(ThemeCard wrapper, Control input)
    {
        input.Enter += (_, _) => wrapper.Emphasis = AppTheme.Accent;
        input.Leave += (_, _) => wrapper.Emphasis = null;
    }

    Control BuildHelpPage()
    {
        var card = AppTheme.NewCard();
        card.Padding = new Padding(12);
        var grid = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = Padding.Empty };
        grid.ColumnStyles.Add(new(SizeType.Absolute, 190));
        grid.ColumnStyles.Add(new(SizeType.Percent, 100));
        var topics = new ListBox { Name = "helpTopics", Dock = DockStyle.Fill, BackColor = AppTheme.Card, ForeColor = AppTheme.Text, BorderStyle = BorderStyle.None, IntegralHeight = false, ItemHeight = 32, DrawMode = DrawMode.OwnerDrawFixed, Margin = new Padding(0, 0, 14, 0), TabIndex = 0, AccessibleName = "Разделы справки" };
        var body = new RichTextBox { Name = "helpBody", Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None, BackColor = AppTheme.Card, ForeColor = AppTheme.Text, Font = AppTheme.Font(10), DetectUrls = false, ScrollBars = RichTextBoxScrollBars.Vertical, TabIndex = 1, AccessibleName = "Содержание справки" };
        AppTheme.DarkNative(topics);
        AppTheme.DarkNative(body);
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
            DrawListRow(e.Graphics, e.Bounds, AppTheme.Card, selected, inset: 0);
            var rect = Rectangle.Inflate(e.Bounds, -10, 0);
            Color textColor = SystemInformation.HighContrast && selected ? SystemColors.HighlightText : AppTheme.Text;
            TextRenderer.DrawText(e.Graphics, (string)topics.Items[e.Index], Font, rect, textColor, TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
            if (SystemInformation.HighContrast)
            {
                e.DrawFocusRectangle();
            }
        };
        topics.SelectedIndexChanged += (_, _) =>
        {
            if (topics.SelectedIndex < 0)
            {
                return;
            }

            var section = HelpContent.Sections[topics.SelectedIndex];
            body.Text = section.Title + Environment.NewLine + Environment.NewLine + section.Body;
            using var headingFont = AppTheme.Font(15, true);
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
            entry.Value.BackColor = active ? AppTheme.Primary : AppTheme.Sidebar;
            entry.Value.ForeColor = active ? AppTheme.PrimaryText : AppTheme.Text;
            entry.Value.Font = active ? navigationFontSelected : navigationFont;
            entry.Value.FlatAppearance.BorderColor = entry.Value.BackColor;
            entry.Value.FlatAppearance.MouseOverBackColor = active ? AppTheme.PrimaryHover : AppTheme.Raised;
            entry.Value.FlatAppearance.MouseDownBackColor = active ? AppTheme.PrimaryPressed : AppTheme.Hover;
            entry.Value.AccessibleDescription = active ? "Текущий раздел" : "Открыть раздел";
        }
        pageTitle.Text = IsCompact ? "Запуск ProxyBridge" : navigation[page].Text;
        SetStatusCardSlim(page != "overview" && !IsCompact);
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
        // Compact startup keeps the taller card: long recovery text must fit.
        SetStatusCardSlim(false);
        contentLayout.RowStyles[1].Height = compact ? CompactStatusHeight : FullStatusHeight;
        openSettings.Visible = compact;
        actionCards.Visible = !compact;
        overviewLayout.RowStyles[0].Height = compact ? 0 : 108;
        MinimumSize = compact ? new Size(740, 570) : new Size(900, 706);
        Size = compact ? new Size(780, 610) : new Size(1080, 806);
    }
    void RefreshOverviewSummary()
    {
        connectionSummary.Text = $"Сохранённый прокси: {settings.Host}:{settings.Port}  ·  EXE: {settings.ExcludedApplications.Length} · Адресов: {settings.ExcludedAddresses.Length}";
        inlineSummary.Text = $"{settings.Host}:{settings.Port}  ·  EXE: {settings.ExcludedApplications.Length} · Адресов: {settings.ExcludedAddresses.Length}";
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
        // Once connected, «Подключить» is no longer the recommended action:
        // it stays available (reconnect) but loses the primary emphasis.
        if (connect is ThemeButton connectButton)
        {
            connectButton.IsPrimary = VisualState != ProxyVisualState.Connected;
            connect.BackColor = connectButton.IsPrimary ? AppTheme.Primary : AppTheme.Raised;
            connect.ForeColor = connectButton.IsPrimary ? AppTheme.PrimaryText : AppTheme.Text;
            connect.FlatAppearance.BorderSize = connectButton.IsPrimary ? 0 : 1;
            connect.FlatAppearance.BorderColor = connectButton.IsPrimary ? AppTheme.Primary : AppTheme.CardBorder;
            connect.FlatAppearance.MouseOverBackColor = connectButton.IsPrimary ? AppTheme.PrimaryHover : AppTheme.Hover;
            connect.FlatAppearance.MouseDownBackColor = connectButton.IsPrimary ? AppTheme.PrimaryPressed : AppTheme.Pressed;
        }
        stateDot.Invalidate();
        RefreshOverviewSummary();
    }
}
