<?php

namespace modules\antispam\src\migrations;

use Craft;
use craft\db\Migration;

class m230101_000002_create_banned_ips_table extends Migration
{
    public function safeUp()
    {
        if (!$this->db->tableExists('{{%antispam_banned_ips}}')) {
            $this->createTable('{{%antispam_banned_ips}}', [
                'id' => $this->primaryKey(),
                'ip_address' => $this->string(45)->notNull()->unique(),
                'reason' => $this->string()->notNull(),
                'banned_at' => $this->dateTime()->notNull(),
            ]);
        }
    }

    public function safeDown()
    {
        $this->dropTableIfExists('{{%antispam_banned_ips}}');
    }
}
