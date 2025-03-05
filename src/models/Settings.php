<?php

namespace modules\antispam\src\models;

use craft\base\Model;

/**
 * Class Settings
 *
 * @package modules\antispam\src\models
 */
class Settings extends Model
{
    /**
     * @var bool
     */
    public bool $enableLogging = false;
    /**
     * @var array|string[]
     */
    public array $allowedCountries = ['SK', 'CZ', 'HU', 'DE'];
    /**
     * @var bool
     */
    public bool $enableIpBlocking = true;
    /**
     * @var bool
     */
    public bool $enablePhoneValidation = true;
    /**
     * @var bool
     */
    public bool $enableHoneypot = true;
    /**
     * @var bool
     */
    public bool $enableSubmissionTimeCheck = true;
    /**
     * @var int
     */
    public int $minSubmissionTime = 3; // Min seconds before allowing submission
    /**
     * @var bool
     */
    public bool $sendWeeklyReport = true;
    /**
     * @var string
     */
    public string $phoneFieldHandle = 'phone';
    /**
     * @var string
     */
    public string $honeypotFieldHandle = 'honeypot';
    /**
     * @var bool
     */
    public bool $enableGeoValidation = true;

    /**
     * @var string|null
     */
    public ?string $weeklyReportEmails = null;

    /**
     * @var bool
     */
    public bool $autoIpBlocking = false;

    /**
     * @var array|string[]
     */
    public array $phoneRegexPatterns = [
        'SK' => '/^\+421\d{9}$/',       // +421 944345046 (normalized)
        'CZ' => '/^\+420\d{9}$/',       // +420 123456789
        'HU' => '/^\+36\d{9}$/',        // +36 123456789
        'DE' => '/^\+49\d{10,11}$/',    // +49 1234567890
        'AT' => '/^\+43\d{9,10}$/',     // +43 123456789
    ];

    /**
     * @return array
     */
    public function rules(): array
    {
        return [
            [['allowedCountries'], 'each', 'rule' => ['string']],
            [['enableIpBlocking', 'enablePhoneValidation', 'enableHoneypot', 'enableSubmissionTimeCheck'], 'boolean'],
            [['minSubmissionTime'], 'integer', 'min' => 1],
        ];
    }
}
