<?php

namespace modules\antispam\src\jobs;

use Craft;
use craft\queue\BaseJob;
use craft\db\Query;
use craft\helpers\Db;
use modules\antispam\src\Antispam;

/**
 * Class SendSpamReport
 *
 * @package modules\antispam\src\jobs
 */
class SendSpamReport extends BaseJob
{
    /**
     * @param $queue
     * @return void
     */
    public function execute($queue): void
    {
        $settings = Antispam::getSettings();
        $reportEmails = $settings->weeklyReportEmails ? explode(',', $settings->weeklyReportEmails) : [];

        // Count spam attempts in the last 7 days
        $spamCount = (new Query())
            ->from('{{%antispam_log}}')
            ->where(['>', 'timestamp', (new \DateTime('-7 days'))->format('Y-m-d H:i:s')])
            ->count();

        // Get system email settings correctly
        $adminEmail = Craft::$app->getProjectConfig()->get('email.fromEmail')
            ?? Craft::$app->getConfig()->getGeneral()->email
            ?? 'admin@yui.sk'; // Fallback email

        // Prepare email content
        $body = "🚨 Weekly Anti-Spam Report 🚨\n\n"
            . "Total spam attempts blocked in the last week: **{$spamCount}**\n\n"
            . "Check the logs in Craft CP → Anti-Spam → Logs.";

        // Merge admin email and report emails, trim whitespace and remove duplicates
        $emails = array_unique(array_merge(
            [$adminEmail],
            array_map('trim', $reportEmails)
        ));

        // Send email to all recipients in one go for best performance
        Craft::$app->getMailer()->compose()
            ->setTo($emails)
            ->setSubject('Weekly Anti-Spam Report')
            ->setTextBody($body)
            ->send();
    }

    /**
     * @return string
     */
    protected function defaultDescription(): string
    {
        return 'Sending weekly anti-spam report';
    }
}
