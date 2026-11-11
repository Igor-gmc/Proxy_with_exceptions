namespace ProxyBridge;

internal sealed class AddressExclusionDialog : Form
{
    readonly TextBox address = new() { Name = "exclusionAddress", Dock = DockStyle.Fill, TabIndex = 0 };
    readonly TextBox port = new() { Name = "exclusionPort", Dock = DockStyle.Fill, TabIndex = 1 };
    readonly Label error = AppTheme.Label("", 9, false, AppTheme.Red);
    ThemeCard addressFrame = null!, portFrame = null!;

    public string? Value { get; private set; }

    public AddressExclusionDialog()
    {
        Name = "addressExclusionDialog";
        Text = "Добавить адрес в исключения";
        Font = AppTheme.Font(10);
        BackColor = AppTheme.Background;
        ForeColor = AppTheme.Text;
        AutoScaleMode = AutoScaleMode.Dpi;
        AutoScaleDimensions = new SizeF(96, 96);
        ClientSize = new Size(620, 324);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        StartPosition = FormStartPosition.CenterParent;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = false;
        Padding = new Padding(24);

        var rows = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 7,
            Margin = Padding.Empty
        };
        rows.ColumnStyles.Add(new(SizeType.Percent, 100));
        foreach (int height in new[] { 24, 44, 50, 24, 44, 50, 44 })
        {
            rows.RowStyles.Add(new(SizeType.Absolute, height));
        }

        rows.Controls.Add(AppTheme.Label("IP-адрес или подсеть", 10), 0, 0);
        addressFrame = StyleInput(address, "IP-адрес или подсеть");
        address.PlaceholderText = "192.168.1.0/24";
        address.AccessibleDescription = "IP-адрес или подсеть; порт можно указать через двоеточие или в отдельном поле ниже.";
        rows.Controls.Add(addressFrame, 0, 1);
        rows.Controls.Add(AppTheme.Label(
            "Например: 192.168.1.0/24, 192.168.1.10:8080 или [fd00::1]:443.\nАдрес действует для всех приложений. DNS (порт 53) не исключается.",
            9, false, AppTheme.Muted), 0, 2);
        rows.Controls.Add(AppTheme.Label("Порт (необязательно)", 10), 0, 3);

        var portRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = Padding.Empty };
        portRow.ColumnStyles.Add(new(SizeType.Absolute, 120));
        portRow.ColumnStyles.Add(new(SizeType.Percent, 100));
        portRow.RowStyles.Add(new(SizeType.Percent, 100));
        portFrame = StyleInput(port, "Порт (необязательно)");
        port.PlaceholderText = "Все порты";
        port.AccessibleDescription = "От 1 до 65535, кроме 53. Оставьте пустым, чтобы исключить все порты, кроме DNS.";
        portRow.Controls.Add(portFrame, 0, 0);
        var portHint = AppTheme.Label("Пусто — все порты, кроме DNS (53).", 9, false, AppTheme.Muted);
        portHint.Margin = new Padding(12, 0, 0, 0);
        portRow.Controls.Add(portHint, 1, 0);
        rows.Controls.Add(portRow, 0, 4);

        error.Name = "addressExclusionError";
        error.AccessibleName = "Ошибка адресного исключения";
        rows.Controls.Add(error, 0, 5);

        error.Font = AppTheme.Font(9, true);
        var add = new ThemeButton { Name = "confirmAddressExclusion", Text = "Добавить", Width = 132, TabIndex = 0 };
        var cancel = new ThemeButton { Name = "cancelAddressExclusion", Text = "Отмена", Width = 116, DialogResult = DialogResult.Cancel, TabIndex = 1 };
        AppTheme.Button(add, primary: true);
        AppTheme.Button(cancel);
        var actions = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft, WrapContents = false, Margin = Padding.Empty };
        actions.Controls.AddRange([cancel, add]);
        rows.Controls.Add(actions, 0, 6);
        Controls.Add(rows);
        AcceptButton = add;
        CancelButton = cancel;
        add.Click += (_, _) => Confirm();
        address.TextChanged += (_, _) => ClearError();
        port.TextChanged += (_, _) => ClearError();
        Shown += (_, _) => address.Focus();
    }

    // Same rounded field as on the «Прокси» page: Accent outline on focus,
    // Red outline (plus the «!» message) on error.
    ThemeCard StyleInput(TextBox input, string accessibleName)
    {
        input.BackColor = AppTheme.Input;
        input.ForeColor = AppTheme.Text;
        input.BorderStyle = BorderStyle.None;
        input.AccessibleName = accessibleName;
        input.Dock = DockStyle.Top;
        input.Margin = Padding.Empty;
        var frame = new ThemeCard { CornerRadius = 8, BackColor = AppTheme.Input, Dock = DockStyle.Fill, Padding = new Padding(10, 7, 10, 4), Margin = new Padding(0, 4, 0, 4) };
        frame.Controls.Add(input);
        input.Enter += (_, _) => { if (frame.Emphasis != AppTheme.Red) { frame.Emphasis = AppTheme.Accent; } };
        input.Leave += (_, _) => { if (frame.Emphasis != AppTheme.Red) { frame.Emphasis = null; } };
        return frame;
    }

    void ClearError()
    {
        error.Text = "";
        addressFrame.Emphasis = address.Focused ? AppTheme.Accent : null;
        portFrame.Emphasis = port.Focused ? AppTheme.Accent : null;
    }

    void ShowError(string message)
    {
        error.Text = "! " + message;
        bool portProblem = !string.IsNullOrWhiteSpace(port.Text);
        addressFrame.Emphasis = AppTheme.Red;
        portFrame.Emphasis = portProblem ? AppTheme.Red : port.Focused ? AppTheme.Accent : null;
    }

    void Confirm()
    {
        try
        {
            var parsed = AddressExclusion.Parse(address.Text);
            if (!string.IsNullOrWhiteSpace(port.Text))
            {
                if (parsed.Port.HasValue)
                {
                    throw new ArgumentException("Порт уже указан в адресе. Очистите отдельное поле порта.");
                }
                string destination = parsed.IsIPv6 ? $"[{parsed.Value}]" : parsed.Value;
                parsed = AddressExclusion.Parse(destination + ":" + port.Text.Trim());
            }

            Value = parsed.Value;
            DialogResult = DialogResult.OK;
        }
        catch (ArgumentException ex)
        {
            ShowError(ex.Message);
        }
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        AppTheme.TryDarkTitleBar(this);
    }
}
