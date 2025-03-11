rule Trojan_AndroidOS_Coper_A_2147787714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Coper.A"
        threat_id = "2147787714"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Coper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "injectsFilled" ascii //weight: 4
        $x_4_2 = "intercept_off" ascii //weight: 4
        $x_4_3 = "devadmin_confirm" ascii //weight: 4
        $x_4_4 = "last_keylog_send" ascii //weight: 4
        $x_4_5 = "RES_PARSE_TASKS" ascii //weight: 4
        $x_4_6 = "EXC_INJ_ACT" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Coper_B_2147845867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Coper.B"
        threat_id = "2147845867"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Coper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/downloadinject?access=" ascii //weight: 2
        $x_2_2 = "startHiddenPush" ascii //weight: 2
        $x_2_3 = "specificBatteryOpt" ascii //weight: 2
        $x_2_4 = "&type=html&botid=" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Coper_A_2147894544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Coper.A!MTB"
        threat_id = "2147894544"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Coper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c4 10 6a 27 6a 27 57 8d bc 24 bb 01 00 00 57 e8 65 1a 00 00 83 c4 10 6a 27 6a 27 ff 74 24 40 57 e8 54 1a 00 00 83 c4 10 6a 27 6a 27 56 57 e8 46 1a 00 00 83 c4 10 6a 27 6a 27 56 89 fe 57 e8 36}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Coper_B_2147915008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Coper.B!MTB"
        threat_id = "2147915008"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Coper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EXC_HIDE_INT" ascii //weight: 1
        $x_1_2 = "verifyappssettingsactivity" ascii //weight: 1
        $x_1_3 = "acsb_pages" ascii //weight: 1
        $x_1_4 = "inj_acsb" ascii //weight: 1
        $x_1_5 = "EXC_SMARTS_SHOW" ascii //weight: 1
        $x_1_6 = "injects_to_disable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Coper_C_2147922855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Coper.C!MTB"
        threat_id = "2147922855"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Coper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 f0 68 ee 05 46 20 68 a7 f1 4e 01 82 69 20 46 90 47 01 46 20 68 a7 f1 56 02 a7 f1 6b 03 d0 f8 84 60 20 46 b0 47 02 46 20 46 29 46 01 f0 52 ee 20 e0 a7 f1 7e 02 a7 f1 a5 03 20 46 a8 47 02 46 20 46 31 46 01 f0 46 ee 05 46 20 68 82 69 4a a9 20 46 90 47 01 46 20 68 a7 f1 e3 03 d0 f8 78 61 48 aa 20 46 b0 47 02 46 20 68 29 46}  //weight: 1, accuracy: High
        $x_1_2 = {10 70 46 f2 61 42 27 f8 23 2c 3f 4a 47 f8 27 2c 3f 4a 47 f8 2b 2c 34 a2 62 f9 cf 0a 14 22 43 f9 02 0a 64 22 1a 80 34 a3 63 f9 cf 0a 1e 23 45 f9 03 0a 43 f6 64 33 28 70 55 46 ad f8 4c 30 07 f8 71 0c 46 f6 6f 60 37 4b 32 4a 27 f8 73 0c 33 48 47 f8 7f 3c 18 23 45 f9 03 0a 47 f8 41 2c 12 92 2d 4a 47 f8 77 0c 47 f8 87 0c 20 68 11 92 2a 4a 2e 4b 10 92 2b 4a 2b 60 47 f8 7b 2c 47 f8 8b 2c 82 69 20 46}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Coper_D_2147928902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Coper.D!MTB"
        threat_id = "2147928902"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Coper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d0 f8 84 60 20 d0 2e aa a7 f1 41 03 20 46 b0 47 02 46 20 46 29 46 01 f0 b6 ef 05 46 20 68 a7 f1 4e 01 82 69 20 46 90 47 01 46 20 68 a7 f1 56 02 a7 f1 6b 03 d0 f8 84 60 20 46 b0 47 02 46 20 46 29 46}  //weight: 1, accuracy: High
        $x_1_2 = {29 46 01 f0 56 ee 20 e0 a7 f1 7e 02 a7 f1 a5 03 20 46 a8 47 02 46 20 46 31 46 01 f0 4a ee 05 46 20 68 82 69 4a a9 20 46 90 47 01 46 20 68 a7 f1 e3 03 d0 f8 78 61 48 aa 20 46}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Coper_E_2147933248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Coper.E!MTB"
        threat_id = "2147933248"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Coper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 b0 be b5 05 af bb 60 0a 4b 7b 44 1c 68 23 68 02 93 07 f1 08 03 05 68 01 93 d5 f8 cc 51 a8 47 21 68 02 9a 91 42 02 bf bd e8 be 40 01 b0 70 47 03 f0 44 ee}  //weight: 1, accuracy: High
        $x_1_2 = {a7 f1 45 03 30 46 a0 47 02 46 30 46 29 46 02 f0 c4 ed 04 46 30 68 a7 f1 52 01 82 69 30 46 90 47 01 46 30 68 a7 f1 5a 02 a7 f1 6f 03 d0 f8 84 50 30 46 a8 47 02 46 30 46}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Coper_F_2147934449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Coper.F!MTB"
        threat_id = "2147934449"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Coper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {f0 b5 03 af 4d f8 04 bd 23 ea e3 7c bc f1 00 0f 27 d0 d0 e9 41 45 ac f1 01 0c 01 34 e6 17 04 eb 16 66 26 f0 ff 06 a4 1b c0 f8 04 41 06 5d 35 44 ee 17 05 eb 16 66 26 f0 ff 06 ad 1b c0 f8 08 51 03 5d 46 5d 06 55 43 55 d0 e9 41 34 04 5d c3 5c 23 44 11 f8 01 4b db b2 c3 5c 63 40 02 f8 01 3b d4 e7 5d f8 04 bb f0 bd d0 b5 02 af 88 5c cc 5c 8c 54 c8 54 d0 bd 01 f0 5d bb 01 f0 5b bb 01 f0 59 bb 70 47}  //weight: 5, accuracy: High
        $x_5_2 = {ad f8 4c 30 07 f8 71 0c 46 f6 6f 60 37 4b 32 4a 27 f8 73 0c 33 48 47 f8 7f 3c 18 23 45 f9 03 0a 47 f8 41 2c 12 92 2d 4a 47 f8 77 0c 47 f8 87 0c 20 68 11 92 2a 4a 2e 4b 10 92 2b 4a 2b 60 47 f8 7b 2c 47 f8 8b 2c 82 69}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Coper_G_2147935639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Coper.G!MTB"
        threat_id = "2147935639"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Coper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "keylogger_start" ascii //weight: 1
        $x_1_2 = "sync_injects" ascii //weight: 1
        $x_1_3 = "disable_battery_task" ascii //weight: 1
        $x_1_4 = "keylogger_task" ascii //weight: 1
        $x_1_5 = "set_bot_mode" ascii //weight: 1
        $x_1_6 = "activate_injects" ascii //weight: 1
        $x_1_7 = "EXC_SMSRCV" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

