rule Trojan_iPhoneOS_WireLurker_A_2147786555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:iPhoneOS/WireLurker.A!xp"
        threat_id = "2147786555"
        type = "Trojan"
        platform = "iPhoneOS: "
        family = "WireLurker"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "www.comeinbaby.com" ascii //weight: 2
        $x_1_2 = "com.baby.apps" ascii //weight: 1
        $x_1_3 = "Z2ER6G3PC7" ascii //weight: 1
        $x_1_4 = "killall SpringBoard" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_iPhoneOS_WireLurker_B_2147808826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:iPhoneOS/WireLurker.B!xp"
        threat_id = "2147808826"
        type = "Trojan"
        platform = "iPhoneOS: "
        family = "WireLurker"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com.bmo.infosec.test.test" ascii //weight: 2
        $x_1_2 = "://www.comeinbaby.com/" ascii //weight: 1
        $x_1_3 = "7854PAABJ8" ascii //weight: 1
        $x_1_4 = "killall SpringBoard" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_iPhoneOS_WireLurker_C_2147814034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:iPhoneOS/WireLurker.C!xp"
        threat_id = "2147814034"
        type = "Trojan"
        platform = "iPhoneOS: "
        family = "WireLurker"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "www.comeinbaby.com" ascii //weight: 2
        $x_1_2 = "/mac/getversion.php" ascii //weight: 1
        $x_1_3 = "/update/update.zip" ascii //weight: 1
        $x_1_4 = "/usr/local/machook/watch.sh" ascii //weight: 1
        $x_1_5 = "kill -HUP SpringBoard" ascii //weight: 1
        $x_1_6 = "start_log/?app=%@&sn=%@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_iPhoneOS_WireLurker_D_2147815022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:iPhoneOS/WireLurker.D!xp"
        threat_id = "2147815022"
        type = "Trojan"
        platform = "iPhoneOS: "
        family = "WireLurker"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com.manhuaba.manhuajb" ascii //weight: 2
        $x_1_2 = "Hunan Langxiong Advertising Decoration Engineering Co" ascii //weight: 1
        $x_1_3 = "597S87B88E" ascii //weight: 1
        $x_1_4 = "://www.manhuaba.com.cn/ad/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

