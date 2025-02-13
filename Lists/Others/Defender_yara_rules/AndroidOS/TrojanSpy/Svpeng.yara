rule TrojanSpy_AndroidOS_Svpeng_A_2147780899_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Svpeng.A!MTB"
        threat_id = "2147780899"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Svpeng"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "seC/vBqix/fBqOuh/pqydQsjylyjO" ascii //weight: 1
        $x_1_2 = "NoNeNoNe" ascii //weight: 1
        $x_1_3 = "smsgrab" ascii //weight: 1
        $x_1_4 = "start_sms_grab" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_AndroidOS_Svpeng_A_2147780899_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Svpeng.A!MTB"
        threat_id = "2147780899"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Svpeng"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "sms_history" ascii //weight: 1
        $x_1_2 = "call_log" ascii //weight: 1
        $x_1_3 = "browser_history" ascii //weight: 1
        $x_1_4 = "card_number" ascii //weight: 1
        $x_1_5 = "save_card" ascii //weight: 1
        $x_1_6 = "FILE_CALLS" ascii //weight: 1
        $x_1_7 = "WARNING! Your device will now reboot to factory settings." ascii //weight: 1
        $x_1_8 = {43 6c 69 63 6b [0-16] 74 6f 20 65 72 61 73 65 20 79 6f 75 72 20 64 61 74 61 20 61 6e 64 20 63 6f 6e 74 69 6e 75 65 [0-8] 66 6f 72 20 63 61 6e 63 65 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Svpeng_B_2147826956_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Svpeng.B!MTB"
        threat_id = "2147826956"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Svpeng"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hitler_backmybewillchangedsoon" ascii //weight: 1
        $x_1_2 = "startplease2" ascii //weight: 1
        $x_1_3 = "ynot_button" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Svpeng_B_2147826956_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Svpeng.B!MTB"
        threat_id = "2147826956"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Svpeng"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kgfbkniose" ascii //weight: 1
        $x_1_2 = "injectslist" ascii //weight: 1
        $x_1_3 = "defsms" ascii //weight: 1
        $x_1_4 = "start_sms_grab" ascii //weight: 1
        $x_1_5 = "bttdlrvave" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Svpeng_C_2147834270_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Svpeng.C!MTB"
        threat_id = "2147834270"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Svpeng"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {39 00 0f 00 38 03 0d 00 12 10 5c 10 ?? 00 59 12 ?? 00 5c 14 ?? 00}  //weight: 1, accuracy: Low
        $x_1_2 = {02 22 05 ce 00 1a 06 02 00 70 20 ?? ?? 65 00 08 00 12 00 6e 20 ?? ?? 05 00 0c 05 6e 10 ?? ?? 05 00 0c 05}  //weight: 1, accuracy: Low
        $x_1_3 = {08 01 24 00 6e 20 ?? ?? 10 00 0c 1c 1a 1d 12 00 74 02 ?? ?? 1c 00 0c 1c 08 00 1c 00 08 01 25 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanSpy_AndroidOS_Svpeng_E_2147840483_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Svpeng.E!MTB"
        threat_id = "2147840483"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Svpeng"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TasksMy" ascii //weight: 1
        $x_1_2 = "save_message.php" ascii //weight: 1
        $x_1_3 = "save_balance" ascii //weight: 1
        $x_1_4 = "ReciveMsg" ascii //weight: 1
        $x_1_5 = "gettask" ascii //weight: 1
        $x_1_6 = "Lcom/android/servicecore/updateapp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Svpeng_D_2147843519_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Svpeng.D!MTB"
        threat_id = "2147843519"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Svpeng"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Outgoin_Phone" ascii //weight: 1
        $x_1_2 = "hideApp" ascii //weight: 1
        $x_1_3 = "setComponentEnabledSetting" ascii //weight: 1
        $x_1_4 = "ACTION_SMS_HISTORY" ascii //weight: 1
        $x_1_5 = "credCardNumber" ascii //weight: 1
        $x_1_6 = "_NUMBER_SEND_TO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

