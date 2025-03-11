# Craft CMS Anti-Spam Module

## 📌 Overview
The **Craft CMS Anti-Spam Module** enhances the [craftcms/contact-form](https://github.com/craftcms/contact-form) plugin by preventing spam submissions with the following features:

- 🌍 **Country-based filtering** – Only allows form submissions from predefined countries.
- 📵 **Phone validation** – Rejects invalid phone numbers based on country format.
- 🚫 **IP logging & blacklisting** – Logs spam attempts and allows manual banning of IPs.
- 🛠 **Admin Panel Management** – View spam logs, ban/unban IPs, and configure settings.
- 🔍 **Honeypot protection** – Blocks bots using hidden fields.
- ⏳ **Submission time check** – Prevents spam by enforcing a minimum time before submission.
- 📊 **Weekly spam report** – Sends an email summary of blocked attempts.

## 📥 Installation

1. **Clone this repository into your `modules/` directory:**
   ```bash
   git clone https://github.com/Gyurkin/craft-antispam.git modules/antispam
   ```
   
2. Enable the module in `config/app.php`:

```php
return [
    'modules' => [
        'antispam' => [
            'class' => \modules\antispam\src\Antispam::class,
        ],
    ],
    'bootstrap' => ['antispam'],
];
```

3. Make sure the modules directory is autoloaded in `composer.json`:

```json
{
  "autoload": {
    "psr-4": {
      "modules\\": "modules/"
    }
  },
}
```

4. Run the database migrations:

```shell
php craft migrate/up
```

5. Clear caches:

```shell
php craft clear-caches/all
```

6. Visit the Craft CMS Control Panel (`/admin`) and navigate to:

- **Anti-Spam Logs** → View blocked attempts.
- **Banned IPs** → Manually ban/unban IPs.
- **Settings** → Configure allowed countries.

## ⚙️ Configuration

### Allowed Countries

Modify the allowed countries in the CP settings or manually update `config/antispam.php`:

```php
return [
    'antispam' => [
        'allowedCountries' => ['SK', 'CZ', 'HU', 'DE', 'AT'],
    ],
];
```

### Banning an IP

You can manually ban an IP via the **Banned IPs** page in the CP or programmatically:

```php
\modules\antispam\Antispam::banIp('192.168.1.1', 'Repeated spam attempts');
```

### Phone Validation

Phone numbers are validated using regex patterns for each country:

```php
'SK' => '/^\+421\d{9}$/',       // +421 944345046 (normalized)
'CZ' => '/^\+420\d{9}$/',       // +420 123456789
'HU' => '/^\+36\d{9}$/',        // +36 123456789
'DE' => '/^\+49\d{10,11}$/',    // +49 1234567890
'AT' => '/^\+43\d{9,10}$/',     // +43 123456789
```

## 📊 Admin Panel Features

Navigate to **Control Panel → Anti-Spam** to access:

- 📜 Spam Logs – View blocked submissions with reasons.
- 🚫 Banned IPs – Manage blacklisted IP addresses.
- ⚙️ Settings – Configure country restrictions.

## 🛠 Customization

### Modify Validation Rules

You can extend the **validatePhone()** method in **Module.php** to add more countries.

### Adjust Spam Prevention Methods

Edit **registerEventHandlers()** in **Module.php** to tweak:

- Submission time limits
- Honeypot field checks
- Custom spam filters

## 🚀 Future Enhancements

- ✅ Auto-ban repeated offenders (configurable threshold)
- ✅ Export logs as CSV
- ✅ Admin dashboard widget for spam insights

## 🤝 Contributing

Pull requests and feature suggestions are welcome!
For issues, please open a ticket in the repository.

## 👨‍💻 Author

Crafted with ❤️ by [Juraj Nagy / YUI s.r.o.]

For questions, contact: [juraj@yui.sk]