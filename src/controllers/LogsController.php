<?php

namespace modules\antispam\src\controllers;

use Craft;
use craft\web\Controller;
use craft\db\Query;
use yii\web\Response;
use craft\helpers\Db;

/**
 * Class LogsController
 *
 * @package modules\antispam\src\controllers
 */
class LogsController extends Controller
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
        $logs = (new Query())
            ->from('{{%antispam_log}}')
            ->orderBy(['timestamp' => SORT_DESC])
            ->limit(100)
            ->all();

        return $this->renderTemplate('antispam/logs', [
            'logs' => $logs,
            'title' => 'Logs'
        ]);
    }

    /**
     * @return mixed
     */
    public function actionClearLogs()
    {
        Craft::$app->getDb()->createCommand()->delete('{{%antispam_log}}')->execute();
        Craft::$app->getSession()->setNotice('Spam logs cleared.');
        return $this->redirect('antispam/logs');
    }

    public function actionBannedIps(): Response
    {
        $bannedIps = (new Query())
            ->from('{{%antispam_banned_ips}}')
            ->orderBy(['banned_at' => SORT_DESC])
            ->all();

        return $this->renderTemplate('antispam/banned-ips', [
            'title' => 'Banned Ips',
            'bannedIps' => $bannedIps,
        ]);
    }

    public function actionBanIp()
    {
        $this->requirePostRequest();
        $request = Craft::$app->getRequest();
        $ip = $request->getBodyParam('ip');
        $reason = $request->getBodyParam('reason', 'Manually banned');

        if (!$ip) {
            throw new BadRequestHttpException('Invalid IP address.');
        }

        // Insert into banned IPs table
        Craft::$app->getDb()->createCommand()->insert('{{%antispam_banned_ips}}', [
            'ip_address' => $ip,
            'reason' => $reason,
            'banned_at' => Db::prepareDateForDb(new \DateTime()),
        ])->execute();

        Craft::$app->getSession()->setNotice("IP {$ip} banned.");
        return $this->redirect('antispam/banned-ips');
    }

    public function actionUnbanIp()
    {
        $this->requirePostRequest();
        $request = Craft::$app->getRequest();
        $ip = $request->getBodyParam('ip');

        if (!$ip) {
            throw new BadRequestHttpException('Invalid IP address.');
        }

        // Remove from banned IPs table
        Craft::$app->getDb()->createCommand()
            ->delete('{{%antispam_banned_ips}}', ['ip_address' => $ip])
            ->execute();

        Craft::$app->getSession()->setNotice("IP {$ip} unbanned.");
        return $this->redirect('antispam/banned-ips');
    }
}
