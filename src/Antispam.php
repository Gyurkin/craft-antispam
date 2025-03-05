<?php

namespace modules\antispam\src;

use Craft;
use yii\base\Module as BaseModule;
use craft\contactform\events\SendEvent;
use craft\contactform\Mailer;
use craft\helpers\Db;
use craft\db\Query;
use yii\base\Event;
use modules\antispam\src\jobs\SendSpamReport;
use craft\web\View;
use craft\events\RegisterTemplateRootsEvent;
use modules\antispam\src\models\Settings;
use craft\i18n\PhpMessageSource;
use yii\base\UserException;

/**
 * Class Antispam
 *
 * @package modules\antispam\src
 */
class Antispam extends BaseModule
{
    /**
     * @var array
     */
    private static array $geoData = [];

    /**
     * @var float|int
     */
    private static float|int $submitTime = 0;

    /**
     * @return void
     * @throws \JsonException
     */
    public function init(): void
    {
        if (!class_exists(\craft\contactform\Mailer::class)) {
            return;
        }

        parent::init();

        // Set an alias for the module
        Craft::setAlias('@antispam', __DIR__);

        Craft::$app->onInit(function() {
            self::runMigrations();

            // Register the 'antispam' translation category using an alias for the basePath.
            Craft::$app->i18n->translations['antispam'] = [
                'class' => PhpMessageSource::class,
                'sourceLanguage' => 'en-US',
                'basePath' => '@antispam/translations',
                'forceTranslation' => true,
                'allowOverrides' => true,
            ];

            self::registerEventHandlers();
            self::registerControlPanel();
            self::scheduleWeeklyReport();
        });
    }

    /**
     * @return void
     * @throws \JsonException
     */
    private static function registerEventHandlers(): void
    {
        // Check if the Contact Form plugin is installed and the Mailer class exists
        if (!class_exists(\craft\contactform\Mailer::class)) {
            Craft::warning('Contact Form plugin is not installed or active. Anti-spam protection will not work.', __METHOD__);
            return;
        }

        // Base template directory
        Event::on(View::class, View::EVENT_REGISTER_CP_TEMPLATE_ROOTS, static function (RegisterTemplateRootsEvent $e) {
            if (is_dir($baseDir = __DIR__ . DIRECTORY_SEPARATOR . 'templates')) {
                $e->roots['antispam'] = $baseDir;
            }
        });

        Event::on(
            Mailer::class,
            Mailer::EVENT_BEFORE_SEND,
            static function (SendEvent $event) {
                if ($event->isSpam) {
                    return;
                }

                $settings = self::getSettings();
                $request = Craft::$app->getRequest();
                $ip = $request->getUserIP();
                $allowedCountries = self::getAllowedCountries();

                // 1. Check if IP is banned
                if ($settings->enableIpBlocking) {
                    if (self::isBannedIp($ip)) {
                        $event->isSpam = true;
                        $event->handled = true;
                        return;
                    }
                }

                // 2. Get user location and validate country
                if ($settings->enableGeoValidation) {
                    $geoData = self::getGeoLocation($ip);
                    if ($geoData && !in_array(strtoupper($geoData['countryCode']), $allowedCountries)) {
                        self::logSpam($ip, Craft::t('antispam', 'Country not allowed: {country}.', ['country' => $geoData['countryCode']]));
                        $event->isSpam = true;
                        $event->handled = true;
                        return;
                    }
                }

                // 3. Validate phone number
                $phoneHandle = $settings->phoneFieldHandle;
                if ($settings->enablePhoneValidation && $phoneHandle && isset($event->submission->message[$phoneHandle])) {
                    $geoData = self::getGeoLocation($ip);
                    if ($geoData && !self::validatePhone($event->submission->message[$phoneHandle] ?? '', strtoupper($geoData['countryCode']))) {
                        self::logSpam($ip, Craft::t('antispam', 'Invalid phone number: {phone}.', ['phone' => $event->submission->message[$phoneHandle]]));
                        $event->isSpam = true;
                        $event->handled = true;
                        return;
                    }
                }

                // 4. Check honeypot field
                $honeypotHandle = $settings->honeypotFieldHandle;
                if ($settings->enableHoneypot && $honeypotHandle) {
                    if (!empty($event->submission->message[$honeypotHandle])) {
                        self::logSpam($ip, Craft::t('antispam', 'Honeypot triggered with value: {honeypot}.', ['honeypot' => $event->submission->message[$honeypotHandle]]));
                        $event->isSpam = true;
                        $event->handled = true;
                        return;
                    }
                }

                // 5. Check submission time
                if ($settings->enableSubmissionTimeCheck) {
                    if (!self::validateSubmissionTime()) {
                        self::logSpam($ip, Craft::t('antispam', 'Form submitted too quickly: {time}s.', [
                            'time' => self::$submitTime
                        ]));
                        $event->isSpam = true;
                        $event->handled = true;
                        return;
                    }
                }
            }
        );

        Event::on(
            \craft\services\Elements::class,
            \craft\services\Elements::EVENT_BEFORE_SAVE_ELEMENT,
            static function(\craft\events\ElementEvent $event) {
                $element = $event->element;

                // Craft Contact Form Extensions
                if ($element instanceof \hybridinteractive\contactformextensions\elements\ContactFormSubmission || $element instanceof  \hybridinteractive\contactformextensions\elements\Submission) {
                    $settings = self::getSettings();
                    $request = Craft::$app->getRequest();
                    $ip = $request->getUserIP();
                    $allowedCountries = self::getAllowedCountries();
                    $data = json_decode($element->message, true, 512, JSON_THROW_ON_ERROR) ?? [];

                    // 1. Check if IP is banned
                    if ($settings->enableIpBlocking) {
                        if (self::isBannedIp($ip)) {
                            // Prevent the save operation by marking the event as invalid.
                            $event->isValid = false;
                        }
                    }

                    // 2. Get user location and validate country
                    if ($settings->enableGeoValidation) {
                        $geoData = self::getGeoLocation($ip);
                        if ($geoData && !in_array(strtoupper($geoData['countryCode']), $allowedCountries)) {
                            self::logSpam($ip, Craft::t('antispam', 'Country not allowed: {country}.', ['country' => $geoData['countryCode']]));
                            // Prevent the save operation by marking the event as invalid.
                            $event->isValid = false;
                        }
                    }

                    // 3. Validate phone number
                    $phoneHandle = $settings->phoneFieldHandle;
                    if ($settings->enablePhoneValidation && $phoneHandle && isset($data[$phoneHandle])) {
                        $geoData = self::getGeoLocation($ip);
                        if ($geoData && !self::validatePhone($data[$phoneHandle], strtoupper($geoData['countryCode']))) {
                            self::logSpam($ip, Craft::t('antispam', 'Invalid phone number: {phone}.', ['phone' => $data[$phoneHandle]]));
                            // Prevent the save operation by marking the event as invalid.
                            $event->isValid = false;
                        }
                    }

                    // 4. Check honeypot field
                    $honeypotHandle = $settings->honeypotFieldHandle;
                    if ($settings->enableHoneypot && $honeypotHandle) {
                        if (!empty($data[$honeypotHandle])) {
                            self::logSpam($ip, Craft::t('antispam', 'Honeypot triggered with value: {honeypot}.', ['honeypot' => $data[$honeypotHandle]]));
                            // Prevent the save operation by marking the event as invalid.
                            $event->isValid = false;
                        }
                    }

                    // 5. Check submission time
                    if ($settings->enableSubmissionTimeCheck) {
                        if (!self::validateSubmissionTime()) {
                            $humanTime = Craft::$app->formatter->asDuration(self::$submitTime);
                            self::logSpam($ip, Craft::t('antispam', 'Form submitted too quickly: {time}.', [
                                'time' => $humanTime
                            ]));
                            // Prevent the save operation by marking the event as invalid.
                            $event->isValid = false;
                        }
                    }

                    if (!$event->isValid) {
                        $element->addError('base', 'Submission prevented due to spam check.');

                        // Throw an exception to halt the process
                        // No other solution stopped the element saving into the DB
                        throw new UserException('Submission prevented due to spam check.');
                    }
                }
            }
        );
    }

    /**
     * @param $ip
     * @return array|null
     * @throws \JsonException
     */
    private static function getGeoLocation($ip): ?array
    {
        if (self::$geoData) {
            // Dont spam the request
            return self::$geoData;
        }

        // If testing locally, the IP might be localhost; use a fallback IP.
        if ($ip === '127.0.0.1' || $ip === '::1') {
            $ip = '8.8.8.8'; // Example fallback (Google's public DNS)
        }

        // Build the API request URL. Here we're using ip-api.com.
        // Https only available for members
        $url = "http://ip-api.com/json/{$ip}";

        // Get the API response
        $response = file_get_contents($url);
        if ($response === false) {
            return null; // Handle error appropriately.
        }

        return self::$geoData = json_decode($response, true, 512, JSON_THROW_ON_ERROR);
    }

    /**
     * @return string[]
     */
    private static function getAllowedCountries(): array
    {
        return Craft::$app->getProjectConfig()->get('antispam.allowedCountries') ?? ['SK', 'CZ', 'HU', 'DE', 'AT'];
    }

    /**
     * @param $phone
     * @param $countryCode
     * @return bool
     */
    private static function validatePhone($phone, $countryCode): bool
    {
        // Load phone validation settings
        $settingsData = Craft::$app->getProjectConfig()->get('antispam') ?? [];
        $settings = new Settings($settingsData);

        $patterns = $settings->phoneRegexPatterns;

        // Normalize the phone number
        $normalizedPhone = self::normalizePhone($phone, $countryCode);

        // Check if regex pattern exists for this country
        if (!isset($patterns[$countryCode])) {
            return false;
        }

        // Validate using regex
        return preg_match($patterns[$countryCode], $normalizedPhone);
    }

    /**
     * Formats phone numbers correctly by adding the country prefix if missing.
     *
     *  Works with the following input formats:
     *  - 00421904430072  → +421904430072
     *  - 421904430072    → +421904430072
     *  - 0904430072      → +421904430072
     *  - 00904430072     → +421904430072
     *  - +421904430072   → +421904430072
     *  - 904430072       → +421904430072
     *  - 4210904430072   → +421904430072
     *  - 421 904 4300 72 → +421904430072
     *  - 0421904430072   → +421904430072
     *
     * @param $phone
     * @param string|null $countryCode
     * @return string
     */
    private static function normalizePhone($phone, ?string $countryCode): string
    {
        if (!$countryCode) {
            return $phone;
        }

        // Remove all spaces
        $phone = str_replace(' ', '', $phone);

        // Get country prefix (e.g., 421 for Slovakia)
        $phonePrefix = self::getPrefixByCountry(strtoupper($countryCode));

        // Remove leading 00, +, or country prefix if present
        $phone = preg_replace('/^(00|\+)?' . $phonePrefix . '/', '', $phone);

        // Ensure the phone number starts with a leading zero
        if (substr($phone, 0, 1) !== '0') {
            $phone = '0' . $phone;
        }

        // Convert leading zero to country code
        if ($phonePrefix) {
            $phone = preg_replace('/^0/', '+' . $phonePrefix, $phone);
        }

        return $phone;
    }

    /**
     * @return bool
     */
    private static function validateSubmissionTime(): bool
    {
        $session = Craft::$app->getSession();
        $startTime = $session->get('formStartTime');
        $session->set('formStartTime', time());

        // Save for logs
        self::$submitTime = time() - $startTime;

        return $startTime && (self::$submitTime > 3); // Block if under 3 sec
    }

    /**
     * @param $ip
     * @param $reason
     * @return void
     */
    private static function logSpam($ip, $reason): void
    {
        $settings = self::getSettings();

        // Auto ban IP
        if ($settings->autoIpBlocking) {
            self::banIp($ip, $reason);
        }

        // Skip if disabled
        if (!$settings->enableLogging) {
            return;
        }

        // If IP is already banned, no need to log again
        if (self::isBannedIp($ip)) {
            return;
        }

        Craft::$app->getDb()->createCommand()->insert('{{%antispam_log}}', [
            'ip_address' => $ip,
            'reason' => $reason,
            'timestamp' => Db::prepareDateForDb(new \DateTime()),
        ])->execute();
    }

    /**
     * @param $ip
     * @return mixed
     */
    private static function isBannedIp($ip): bool
    {
        return (new Query())
            ->from('{{%antispam_banned_ips}}')
            ->where(['ip_address' => $ip])
            ->exists();
    }

    /**
     * @param $ip
     * @param $reason
     * @return void
     */
    public static function banIp($ip, $reason): void
    {
        if (!self::isBannedIp($ip)) {
            Craft::$app->getDb()->createCommand()->insert('{{%antispam_banned_ips}}', [
                'ip_address' => $ip,
                'reason' => $reason,
                'banned_at' => Db::prepareDateForDb(new \DateTime()),
            ])->execute();
        }
    }

    /**
     * @return void
     */
    private static function registerControlPanel(): void
    {
        Event::on(
            \craft\web\twig\variables\Cp::class,
            \craft\web\twig\variables\Cp::EVENT_REGISTER_CP_NAV_ITEMS,
            static function (\craft\events\RegisterCpNavItemsEvent $event) {
                $event->navItems[] = [
                    'label' => Craft::t('antispam', 'Anti-Spam'),
                    'url' => 'antispam/logs',
                    'icon' => Craft::getAlias('@antispam/resources/icon.svg'),
                    'subnav' => [
                        'logs' => ['label' => Craft::t('antispam', 'Spam Logs'), 'url' => 'antispam/logs'],
                        'bannedIps' => ['label' => Craft::t('antispam', 'Banned IPs'), 'url' => 'antispam/banned-ips'],
                        'settings' => ['label' => Craft::t('antispam', 'Settings'), 'url' => 'antispam/settings'],
                    ],
                ];
            }
        );

        Event::on(
            \craft\web\UrlManager::class,
            \craft\web\UrlManager::EVENT_REGISTER_CP_URL_RULES,
            static function (\craft\events\RegisterUrlRulesEvent $event) {
                $event->rules['antispam/logs'] = 'antispam/logs/index';
                $event->rules['antispam/logs/clear-logs'] = 'antispam/logs/clear-logs';
                $event->rules['antispam/banned-ips'] = 'antispam/logs/banned-ips';
                $event->rules['antispam/banned-ips/ban-ip'] = 'antispam/logs/ban-ip';
                $event->rules['antispam/banned-ips/unban-ip'] = 'antispam/logs/unban-ip';
                $event->rules['antispam/settings'] = 'antispam/settings';
                $event->rules['antispam/settings/save'] = 'antispam/settings/save';
            }
        );
    }

    /**
     * @return void
     */
    private static function scheduleWeeklyReport(): void
    {
        $settingsData = Craft::$app->getProjectConfig()->get('antispam') ?? [];
        $settings = new Settings($settingsData); // Convert array to Settings model

        // Only schedule the job if enabled
        if (!$settings->sendWeeklyReport) {
            return;
        }

        $queue = Craft::$app->getQueue();

        // Ensure only one instance of the job runs per week
        $existingJob = (new Query())
            ->from('{{%queue}}')
            ->where(['description' => 'Sending weekly anti-spam report'])
            ->exists();

        if (!$existingJob) {
            $queue->delay(60 * 60 * 24 * 7) // Delay by 1 week (in seconds)
            ->push(new SendSpamReport());
        }
    }

    /**
     * @return void
     */
    private static function runMigrations(): void
    {
        $migrator = Craft::$app->getMigrator();
        $migrationsPath = Craft::getAlias('@antispam/migrations');

        if (is_dir($migrationsPath)) {
            // Fetch applied migrations
            $appliedMigrations = array_keys($migrator->getMigrationHistory(9999)); // Use a large limit

            foreach (glob($migrationsPath . '/*.php') as $file) {
                $migrationName = pathinfo($file, PATHINFO_FILENAME);
                $migrationClass = 'modules\\antispam\\src\\migrations\\' . $migrationName;

                // Check if migration has already been applied
                if (!in_array($migrationName, $appliedMigrations, true)) {
                    Craft::info("Running migration: {$migrationClass}", __METHOD__);
                    $migrator->migrateUp(new $migrationClass);
                } else {
                    Craft::info("Skipping already applied migration: {$migrationClass}", __METHOD__);
                }
            }
        }
    }

    /**
     * @return Settings
     */
    public static function getSettingsModel(): Settings
    {
        return new Settings();
    }

    /**
     * @return string|null
     */
    public static function getCpSettingsUrl(): ?string
    {
        return 'antispam/settings';
    }

    /**
     * @return Settings
     */
    public static function getSettings(): Settings
    {
        $settingsData = Craft::$app->getProjectConfig()->get('antispam');
        return new Settings($settingsData);
    }

    /**
     * @param $countryCode
     * @return string|null
     */
    private static function getPrefixByCountry($countryCode): ?string
    {
        $countryArray = [
            'AD'=> ['name'=>'ANDORRA','code'=>'376'],
            'AE'=> ['name'=>'UNITED ARAB EMIRATES','code'=>'971'],
            'AF'=> ['name'=>'AFGHANISTAN','code'=>'93'],
            'AG'=> ['name'=>'ANTIGUA AND BARBUDA','code'=>'1268'],
            'AI'=> ['name'=>'ANGUILLA','code'=>'1264'],
            'AL'=> ['name'=>'ALBANIA','code'=>'355'],
            'AM'=> ['name'=>'ARMENIA','code'=>'374'],
            'AN'=> ['name'=>'NETHERLANDS ANTILLES','code'=>'599'],
            'AO'=> ['name'=>'ANGOLA','code'=>'244'],
            'AQ'=> ['name'=>'ANTARCTICA','code'=>'672'],
            'AR'=> ['name'=>'ARGENTINA','code'=>'54'],
            'AS'=> ['name'=>'AMERICAN SAMOA','code'=>'1684'],
            'AT'=> ['name'=>'AUSTRIA','code'=>'43'],
            'AU'=> ['name'=>'AUSTRALIA','code'=>'61'],
            'AW'=> ['name'=>'ARUBA','code'=>'297'],
            'AZ'=> ['name'=>'AZERBAIJAN','code'=>'994'],
            'BA'=> ['name'=>'BOSNIA AND HERZEGOVINA','code'=>'387'],
            'BB'=> ['name'=>'BARBADOS','code'=>'1246'],
            'BD'=> ['name'=>'BANGLADESH','code'=>'880'],
            'BE'=> ['name'=>'BELGIUM','code'=>'32'],
            'BF'=> ['name'=>'BURKINA FASO','code'=>'226'],
            'BG'=> ['name'=>'BULGARIA','code'=>'359'],
            'BH'=> ['name'=>'BAHRAIN','code'=>'973'],
            'BI'=> ['name'=>'BURUNDI','code'=>'257'],
            'BJ'=> ['name'=>'BENIN','code'=>'229'],
            'BL'=> ['name'=>'SAINT BARTHELEMY','code'=>'590'],
            'BM'=> ['name'=>'BERMUDA','code'=>'1441'],
            'BN'=> ['name'=>'BRUNEI DARUSSALAM','code'=>'673'],
            'BO'=> ['name'=>'BOLIVIA','code'=>'591'],
            'BR'=> ['name'=>'BRAZIL','code'=>'55'],
            'BS'=> ['name'=>'BAHAMAS','code'=>'1242'],
            'BT'=> ['name'=>'BHUTAN','code'=>'975'],
            'BW'=> ['name'=>'BOTSWANA','code'=>'267'],
            'BY'=> ['name'=>'BELARUS','code'=>'375'],
            'BZ'=> ['name'=>'BELIZE','code'=>'501'],
            'CA'=> ['name'=>'CANADA','code'=>'1'],
            'CC'=> ['name'=>'COCOS (KEELING) ISLANDS','code'=>'61'],
            'CD'=> ['name'=>'CONGO, THE DEMOCRATIC REPUBLIC OF THE','code'=>'243'],
            'CF'=> ['name'=>'CENTRAL AFRICAN REPUBLIC','code'=>'236'],
            'CG'=> ['name'=>'CONGO','code'=>'242'],
            'CH'=> ['name'=>'SWITZERLAND','code'=>'41'],
            'CI'=> ['name'=>'COTE D IVOIRE','code'=>'225'],
            'CK'=> ['name'=>'COOK ISLANDS','code'=>'682'],
            'CL'=> ['name'=>'CHILE','code'=>'56'],
            'CM'=> ['name'=>'CAMEROON','code'=>'237'],
            'CN'=> ['name'=>'CHINA','code'=>'86'],
            'CO'=> ['name'=>'COLOMBIA','code'=>'57'],
            'CR'=> ['name'=>'COSTA RICA','code'=>'506'],
            'CU'=> ['name'=>'CUBA','code'=>'53'],
            'CV'=> ['name'=>'CAPE VERDE','code'=>'238'],
            'CX'=> ['name'=>'CHRISTMAS ISLAND','code'=>'61'],
            'CY'=> ['name'=>'CYPRUS','code'=>'357'],
            'CZ'=> ['name'=>'CZECH REPUBLIC','code'=>'420'],
            'DE'=> ['name'=>'GERMANY','code'=>'49'],
            'DJ'=> ['name'=>'DJIBOUTI','code'=>'253'],
            'DK'=> ['name'=>'DENMARK','code'=>'45'],
            'DM'=> ['name'=>'DOMINICA','code'=>'1767'],
            'DO'=> ['name'=>'DOMINICAN REPUBLIC','code'=>'1809'],
            'DZ'=> ['name'=>'ALGERIA','code'=>'213'],
            'EC'=> ['name'=>'ECUADOR','code'=>'593'],
            'EE'=> ['name'=>'ESTONIA','code'=>'372'],
            'EG'=> ['name'=>'EGYPT','code'=>'20'],
            'ER'=> ['name'=>'ERITREA','code'=>'291'],
            'ES'=> ['name'=>'SPAIN','code'=>'34'],
            'ET'=> ['name'=>'ETHIOPIA','code'=>'251'],
            'FI'=> ['name'=>'FINLAND','code'=>'358'],
            'FJ'=> ['name'=>'FIJI','code'=>'679'],
            'FK'=> ['name'=>'FALKLAND ISLANDS (MALVINAS)','code'=>'500'],
            'FM'=> ['name'=>'MICRONESIA, FEDERATED STATES OF','code'=>'691'],
            'FO'=> ['name'=>'FAROE ISLANDS','code'=>'298'],
            'FR'=> ['name'=>'FRANCE','code'=>'33'],
            'GA'=> ['name'=>'GABON','code'=>'241'],
            'GB'=> ['name'=>'UNITED KINGDOM','code'=>'44'],
            'GD'=> ['name'=>'GRENADA','code'=>'1473'],
            'GE'=> ['name'=>'GEORGIA','code'=>'995'],
            'GH'=> ['name'=>'GHANA','code'=>'233'],
            'GI'=> ['name'=>'GIBRALTAR','code'=>'350'],
            'GL'=> ['name'=>'GREENLAND','code'=>'299'],
            'GM'=> ['name'=>'GAMBIA','code'=>'220'],
            'GN'=> ['name'=>'GUINEA','code'=>'224'],
            'GQ'=> ['name'=>'EQUATORIAL GUINEA','code'=>'240'],
            'GR'=> ['name'=>'GREECE','code'=>'30'],
            'GT'=> ['name'=>'GUATEMALA','code'=>'502'],
            'GU'=> ['name'=>'GUAM','code'=>'1671'],
            'GW'=> ['name'=>'GUINEA-BISSAU','code'=>'245'],
            'GY'=> ['name'=>'GUYANA','code'=>'592'],
            'HK'=> ['name'=>'HONG KONG','code'=>'852'],
            'HN'=> ['name'=>'HONDURAS','code'=>'504'],
            'HR'=> ['name'=>'CROATIA','code'=>'385'],
            'HT'=> ['name'=>'HAITI','code'=>'509'],
            'HU'=> ['name'=>'HUNGARY','code'=>'36'],
            'ID'=> ['name'=>'INDONESIA','code'=>'62'],
            'IE'=> ['name'=>'IRELAND','code'=>'353'],
            'IL'=> ['name'=>'ISRAEL','code'=>'972'],
            'IM'=> ['name'=>'ISLE OF MAN','code'=>'44'],
            'IN'=> ['name'=>'INDIA','code'=>'91'],
            'IQ'=> ['name'=>'IRAQ','code'=>'964'],
            'IR'=> ['name'=>'IRAN, ISLAMIC REPUBLIC OF','code'=>'98'],
            'IS'=> ['name'=>'ICELAND','code'=>'354'],
            'IT'=> ['name'=>'ITALY','code'=>'39'],
            'JM'=> ['name'=>'JAMAICA','code'=>'1876'],
            'JO'=> ['name'=>'JORDAN','code'=>'962'],
            'JP'=> ['name'=>'JAPAN','code'=>'81'],
            'KE'=> ['name'=>'KENYA','code'=>'254'],
            'KG'=> ['name'=>'KYRGYZSTAN','code'=>'996'],
            'KH'=> ['name'=>'CAMBODIA','code'=>'855'],
            'KI'=> ['name'=>'KIRIBATI','code'=>'686'],
            'KM'=> ['name'=>'COMOROS','code'=>'269'],
            'KN'=> ['name'=>'SAINT KITTS AND NEVIS','code'=>'1869'],
            'KP'=> ['name'=>'KOREA DEMOCRATIC PEOPLES REPUBLIC OF','code'=>'850'],
            'KR'=> ['name'=>'KOREA REPUBLIC OF','code'=>'82'],
            'KW'=> ['name'=>'KUWAIT','code'=>'965'],
            'KY'=> ['name'=>'CAYMAN ISLANDS','code'=>'1345'],
            'KZ'=> ['name'=>'KAZAKSTAN','code'=>'7'],
            'LA'=> ['name'=>'LAO PEOPLES DEMOCRATIC REPUBLIC','code'=>'856'],
            'LB'=> ['name'=>'LEBANON','code'=>'961'],
            'LC'=> ['name'=>'SAINT LUCIA','code'=>'1758'],
            'LI'=> ['name'=>'LIECHTENSTEIN','code'=>'423'],
            'LK'=> ['name'=>'SRI LANKA','code'=>'94'],
            'LR'=> ['name'=>'LIBERIA','code'=>'231'],
            'LS'=> ['name'=>'LESOTHO','code'=>'266'],
            'LT'=> ['name'=>'LITHUANIA','code'=>'370'],
            'LU'=> ['name'=>'LUXEMBOURG','code'=>'352'],
            'LV'=> ['name'=>'LATVIA','code'=>'371'],
            'LY'=> ['name'=>'LIBYAN ARAB JAMAHIRIYA','code'=>'218'],
            'MA'=> ['name'=>'MOROCCO','code'=>'212'],
            'MC'=> ['name'=>'MONACO','code'=>'377'],
            'MD'=> ['name'=>'MOLDOVA, REPUBLIC OF','code'=>'373'],
            'ME'=> ['name'=>'MONTENEGRO','code'=>'382'],
            'MF'=> ['name'=>'SAINT MARTIN','code'=>'1599'],
            'MG'=> ['name'=>'MADAGASCAR','code'=>'261'],
            'MH'=> ['name'=>'MARSHALL ISLANDS','code'=>'692'],
            'MK'=> ['name'=>'MACEDONIA, THE FORMER YUGOSLAV REPUBLIC OF','code'=>'389'],
            'ML'=> ['name'=>'MALI','code'=>'223'],
            'MM'=> ['name'=>'MYANMAR','code'=>'95'],
            'MN'=> ['name'=>'MONGOLIA','code'=>'976'],
            'MO'=> ['name'=>'MACAU','code'=>'853'],
            'MP'=> ['name'=>'NORTHERN MARIANA ISLANDS','code'=>'1670'],
            'MR'=> ['name'=>'MAURITANIA','code'=>'222'],
            'MS'=> ['name'=>'MONTSERRAT','code'=>'1664'],
            'MT'=> ['name'=>'MALTA','code'=>'356'],
            'MU'=> ['name'=>'MAURITIUS','code'=>'230'],
            'MV'=> ['name'=>'MALDIVES','code'=>'960'],
            'MW'=> ['name'=>'MALAWI','code'=>'265'],
            'MX'=> ['name'=>'MEXICO','code'=>'52'],
            'MY'=> ['name'=>'MALAYSIA','code'=>'60'],
            'MZ'=> ['name'=>'MOZAMBIQUE','code'=>'258'],
            'NA'=> ['name'=>'NAMIBIA','code'=>'264'],
            'NC'=> ['name'=>'NEW CALEDONIA','code'=>'687'],
            'NE'=> ['name'=>'NIGER','code'=>'227'],
            'NG'=> ['name'=>'NIGERIA','code'=>'234'],
            'NI'=> ['name'=>'NICARAGUA','code'=>'505'],
            'NL'=> ['name'=>'NETHERLANDS','code'=>'31'],
            'NO'=> ['name'=>'NORWAY','code'=>'47'],
            'NP'=> ['name'=>'NEPAL','code'=>'977'],
            'NR'=> ['name'=>'NAURU','code'=>'674'],
            'NU'=> ['name'=>'NIUE','code'=>'683'],
            'NZ'=> ['name'=>'NEW ZEALAND','code'=>'64'],
            'OM'=> ['name'=>'OMAN','code'=>'968'],
            'PA'=> ['name'=>'PANAMA','code'=>'507'],
            'PE'=> ['name'=>'PERU','code'=>'51'],
            'PF'=> ['name'=>'FRENCH POLYNESIA','code'=>'689'],
            'PG'=> ['name'=>'PAPUA NEW GUINEA','code'=>'675'],
            'PH'=> ['name'=>'PHILIPPINES','code'=>'63'],
            'PK'=> ['name'=>'PAKISTAN','code'=>'92'],
            'PL'=> ['name'=>'POLAND','code'=>'48'],
            'PM'=> ['name'=>'SAINT PIERRE AND MIQUELON','code'=>'508'],
            'PN'=> ['name'=>'PITCAIRN','code'=>'870'],
            'PR'=> ['name'=>'PUERTO RICO','code'=>'1'],
            'PT'=> ['name'=>'PORTUGAL','code'=>'351'],
            'PW'=> ['name'=>'PALAU','code'=>'680'],
            'PY'=> ['name'=>'PARAGUAY','code'=>'595'],
            'QA'=> ['name'=>'QATAR','code'=>'974'],
            'RO'=> ['name'=>'ROMANIA','code'=>'40'],
            'RS'=> ['name'=>'SERBIA','code'=>'381'],
            'RU'=> ['name'=>'RUSSIAN FEDERATION','code'=>'7'],
            'RW'=> ['name'=>'RWANDA','code'=>'250'],
            'SA'=> ['name'=>'SAUDI ARABIA','code'=>'966'],
            'SB'=> ['name'=>'SOLOMON ISLANDS','code'=>'677'],
            'SC'=> ['name'=>'SEYCHELLES','code'=>'248'],
            'SD'=> ['name'=>'SUDAN','code'=>'249'],
            'SE'=> ['name'=>'SWEDEN','code'=>'46'],
            'SG'=> ['name'=>'SINGAPORE','code'=>'65'],
            'SH'=> ['name'=>'SAINT HELENA','code'=>'290'],
            'SI'=> ['name'=>'SLOVENIA','code'=>'386'],
            'SK'=> ['name'=>'SLOVAKIA','code'=>'421'],
            'SL'=> ['name'=>'SIERRA LEONE','code'=>'232'],
            'SM'=> ['name'=>'SAN MARINO','code'=>'378'],
            'SN'=> ['name'=>'SENEGAL','code'=>'221'],
            'SO'=> ['name'=>'SOMALIA','code'=>'252'],
            'SR'=> ['name'=>'SURINAME','code'=>'597'],
            'ST'=> ['name'=>'SAO TOME AND PRINCIPE','code'=>'239'],
            'SV'=> ['name'=>'EL SALVADOR','code'=>'503'],
            'SY'=> ['name'=>'SYRIAN ARAB REPUBLIC','code'=>'963'],
            'SZ'=> ['name'=>'SWAZILAND','code'=>'268'],
            'TC'=> ['name'=>'TURKS AND CAICOS ISLANDS','code'=>'1649'],
            'TD'=> ['name'=>'CHAD','code'=>'235'],
            'TG'=> ['name'=>'TOGO','code'=>'228'],
            'TH'=> ['name'=>'THAILAND','code'=>'66'],
            'TJ'=> ['name'=>'TAJIKISTAN','code'=>'992'],
            'TK'=> ['name'=>'TOKELAU','code'=>'690'],
            'TL'=> ['name'=>'TIMOR-LESTE','code'=>'670'],
            'TM'=> ['name'=>'TURKMENISTAN','code'=>'993'],
            'TN'=> ['name'=>'TUNISIA','code'=>'216'],
            'TO'=> ['name'=>'TONGA','code'=>'676'],
            'TR'=> ['name'=>'TURKEY','code'=>'90'],
            'TT'=> ['name'=>'TRINIDAD AND TOBAGO','code'=>'1868'],
            'TV'=> ['name'=>'TUVALU','code'=>'688'],
            'TW'=> ['name'=>'TAIWAN, PROVINCE OF CHINA','code'=>'886'],
            'TZ'=> ['name'=>'TANZANIA, UNITED REPUBLIC OF','code'=>'255'],
            'UA'=> ['name'=>'UKRAINE','code'=>'380'],
            'UG'=> ['name'=>'UGANDA','code'=>'256'],
            'US'=> ['name'=>'UNITED STATES','code'=>'1'],
            'UY'=> ['name'=>'URUGUAY','code'=>'598'],
            'UZ'=> ['name'=>'UZBEKISTAN','code'=>'998'],
            'VA'=> ['name'=>'HOLY SEE (VATICAN CITY STATE)','code'=>'39'],
            'VC'=> ['name'=>'SAINT VINCENT AND THE GRENADINES','code'=>'1784'],
            'VE'=> ['name'=>'VENEZUELA','code'=>'58'],
            'VG'=> ['name'=>'VIRGIN ISLANDS, BRITISH','code'=>'1284'],
            'VI'=> ['name'=>'VIRGIN ISLANDS, U.S.','code'=>'1340'],
            'VN'=> ['name'=>'VIET NAM','code'=>'84'],
            'VU'=> ['name'=>'VANUATU','code'=>'678'],
            'WF'=> ['name'=>'WALLIS AND FUTUNA','code'=>'681'],
            'WS'=> ['name'=>'SAMOA','code'=>'685'],
            'XK'=> ['name'=>'KOSOVO','code'=>'381'],
            'YE'=> ['name'=>'YEMEN','code'=>'967'],
            'YT'=> ['name'=>'MAYOTTE','code'=>'262'],
            'ZA'=> ['name'=>'SOUTH AFRICA','code'=>'27'],
            'ZM'=> ['name'=>'ZAMBIA','code'=>'260'],
            'ZW'=> ['name'=>'ZIMBABWE','code'=>'263']
        ];

        if (isset($countryArray[$countryCode])) {
            $countryData = $countryArray[$countryCode];

            return $countryData['code'];
        }

        return null;
    }
}
