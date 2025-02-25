<?php

namespace modules\antispam\src\controllers;

use Craft;
use craft\web\Controller;
use modules\antispam\src\models\Settings;
use yii\web\Response;

/**
 * Class SettingsController
 *
 * @package modules\antispam\src\controllers
 */
class SettingsController extends Controller
{
    /**
     * @var array|int|bool
     */
    protected array|int|bool $allowAnonymous = false;

    /**
     * @return Response
     */
    public function actionIndex(): Response
    {
        $settingsData = Craft::$app->getProjectConfig()->get('antispam') ?? [];
        $settings = new Settings($settingsData);

        // Get Craft's built-in country list (ISO 3166-1 alpha-2 codes)
        $countries = Craft::$app->getAddresses()->getCountryRepository()->getList('en');

        // Convert phone regex patterns into an array of objects for editableTable
        $formattedPatterns = [];
        foreach ($settings->phoneRegexPatterns as $country => $regex) {
            $formattedPatterns[] = [
                'country' => $country,
                'regex' => $regex
            ];
        }

        return $this->renderTemplate('antispam/settings', [
            'title' => 'Settings',
            'settings' => $settings,
            'countries' => $countries,
            'phoneRegexPatterns' => $formattedPatterns
        ]);
    }

    /**
     * @return Response|null
     */
    public function actionSave(): ?Response
    {
        $this->requirePostRequest();
        $request = Craft::$app->getRequest();

        $allowedCountries = $request->getBodyParam('allowedCountries', []);
        $phoneRegexPatterns = $request->getBodyParam('phoneRegexPatterns', []);

        // Ensure only valid country codes are saved
        $validCountries = array_keys(Craft::$app->getAddresses()->getCountryRepository()->getList('en'));
        $allowedCountries = array_intersect($allowedCountries, $validCountries);

        // Convert phone validation rules into a key-value associative array
        $validatedPatterns = [];
        foreach ($phoneRegexPatterns as $pattern) {
            if (!empty($pattern['country']) && !empty($pattern['regex'])) {
                $validatedPatterns[$pattern['country']] = $pattern['regex'];
            }
        }

        $settings = new Settings([
            'allowedCountries' => $allowedCountries,
            'phoneRegexPatterns' => $validatedPatterns, // Save correctly
            'enableLogging' => (bool) $request->getBodyParam('enableLogging'),
            'enableIpBlocking' => (bool) $request->getBodyParam('enableIpBlocking'),
            'minSubmissionTime' => (int) $request->getBodyParam('minSubmissionTime', 3),
            'sendWeeklyReport' => (bool) $request->getBodyParam('sendWeeklyReport'),
            'enablePhoneValidation' => (bool) $request->getBodyParam('enablePhoneValidation'),
            'phoneFieldHandle' => (string) $request->getBodyParam('phoneFieldHandle'),
            'enableHoneypot' => (bool) $request->getBodyParam('enableHoneypot'),
            'honeypotFieldHandle' => (string)$request->getBodyParam('honeypotFieldHandle'),
            'weeklyReportEmails' => (string)$request->getBodyParam('weeklyReportEmails'),
        ]);

        Craft::$app->getProjectConfig()->set('antispam', $settings->toArray());
        Craft::$app->getSession()->setNotice('Settings saved.');

        return $this->redirect('antispam/settings');
    }
}
