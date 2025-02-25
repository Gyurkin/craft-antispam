<?php

namespace modules\antispam\src\controllers;

use Craft;
use craft\web\Controller;
use craft\db\Query;
use yii\web\Response;
use craft\helpers\Db;
use \yii\web\BadRequestHttpException;

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
            'title' => Craft::t('antispam', 'Logs')
        ]);
    }

    /**
     * @return Response|null
     */
    public function actionClearLogs(): ?Response
    {
        Craft::$app->getDb()->createCommand()->delete('{{%antispam_log}}')->execute();
        Craft::$app->getSession()->setNotice(Craft::t('antispam', 'Spam logs cleared.'));

        return $this->redirect('antispam/logs');
    }

    /**
     * @return Response|null
     */
    public function actionBannedIps(): ?Response
    {
        $bannedIps = (new Query())
            ->from('{{%antispam_banned_ips}}')
            ->orderBy(['banned_at' => SORT_DESC])
            ->all();

        return $this->renderTemplate('antispam/banned-ips', [
            'title' => Craft::t('antispam', 'Banned Ips'),
            'bannedIps' => $bannedIps,
        ]);
    }

    /**
     * @return Response|null
     */
    public function actionBanIp(): ?Response
    {
        $this->requirePostRequest();
        $request = Craft::$app->getRequest();
        $ip = $request->getBodyParam('ip');
        $reason = $request->getBodyParam('reason', Craft::t('antispam', 'Manually banned'));

        if (!$ip) {
            Craft::$app->getSession()->setError(Craft::t('antispam', 'Invalid IP address.'));
            return $this->redirect('antispam/banned-ips');
        }

        // Insert into banned IPs table
        Craft::$app->getDb()->createCommand()->insert('{{%antispam_banned_ips}}', [
            'ip_address' => $ip,
            'reason' => $reason,
            'banned_at' => Db::prepareDateForDb(new \DateTime()),
        ])->execute();

        Craft::$app->getSession()->setNotice(Craft::t('antispam', "IP {ip} banned.", ['ip' => $ip]));
        return $this->redirect('antispam/banned-ips');
    }

    /**
     * @return Response|null
     */
    public function actionUnbanIp(): ?Response
    {
        $this->requirePostRequest();

        $request = Craft::$app->getRequest();
        $ids = $request->getBodyParam('ids');

        if (empty($ids)) {
            return $this->redirect('antispam/banned-ips');
        }

        // Ensure $ids is an array even if a single ID is provided
        if (!is_array($ids)) {
            $ids = [$ids];
        }

        // Delete banned IP entries by their IDs
        Craft::$app->getDb()->createCommand()
            ->delete('{{%antispam_banned_ips}}', ['id' => $ids])
            ->execute();

        Craft::$app->getSession()->setNotice(Craft::t('antispam', "Selected IP(s) unbanned."));
        return $this->redirect('antispam/banned-ips');
    }
}
