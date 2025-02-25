<?php

namespace modules\antispam\src\migrations;

use Craft;
use craft\db\Migration;

class m230101_000001_create_antispam_log_table extends Migration
{
    public function safeUp()
    {
        if (!$this->db->tableExists('{{%antispam_log}}')) {
            $this->createTable('{{%antispam_log}}', [
                'id' => $this->primaryKey(),
                'ip_address' => $this->string(45)->notNull(),
                'reason' => $this->string()->notNull(),
                'timestamp' => $this->dateTime()->notNull(),
            ]);
        }
    }

    public function safeDown()
    {
        $this->dropTableIfExists('{{%antispam_log}}');
    }
}
