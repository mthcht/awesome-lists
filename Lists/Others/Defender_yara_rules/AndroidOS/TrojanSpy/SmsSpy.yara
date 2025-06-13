rule TrojanSpy_AndroidOS_SmsSpy_G_2147780678_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsSpy.G!MTB"
        threat_id = "2147780678"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/phone2/stop/activity/DeleteActivity" ascii //weight: 1
        $x_1_2 = "Lcom/phone/stop6/service/SmsService" ascii //weight: 1
        $x_1_3 = "content://sms/conversations/" ascii //weight: 1
        $x_1_4 = "has_send_phone_info" ascii //weight: 1
        $x_1_5 = "has_send_contacts" ascii //weight: 1
        $x_1_6 = "has_set_send_email_pwd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsSpy_BH_2147786557_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsSpy.BH!xp"
        threat_id = "2147786557"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "org/red/cute/activity" ascii //weight: 1
        $x_1_2 = "/Android/Sma/Log" ascii //weight: 1
        $x_1_3 = {53 6d 73 55 70 6c 6f 61 64 4d 61 6e 61 67 65 72 20 72 65 73 70 6f 6e 73 65 ef bc 9a}  //weight: 1, accuracy: High
        $x_1_4 = "GetPackageNameService" ascii //weight: 1
        $x_1_5 = "CallLogMonitor" ascii //weight: 1
        $x_1_6 = "SmsMonitor" ascii //weight: 1
        $x_1_7 = {43 6f 6e 74 61 63 74 55 70 6c 6f 61 64 4d 61 6e 61 67 65 72 20 72 65 73 70 6f 6e 73 65 ef bc 9a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsSpy_E_2147793711_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsSpy.E!xp"
        threat_id = "2147793711"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "smspay" ascii //weight: 1
        $x_1_2 = "sms_link_id" ascii //weight: 1
        $x_1_3 = "http://vpay.api.eerichina.com/api/payment" ascii //weight: 1
        $x_1_4 = "com/wyzf/plugin/net" ascii //weight: 1
        $x_1_5 = "Lcom//x90/x02/x15/plugin/model/SmsInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_SmsSpy_C_2147808868_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsSpy.C"
        threat_id = "2147808868"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DiviceInfo" ascii //weight: 1
        $x_1_2 = "&port=fuckmars" ascii //weight: 1
        $x_1_3 = "/rat.php" ascii //weight: 1
        $x_1_4 = "/upload.php?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsSpy_H_2147815377_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsSpy.H!MTB"
        threat_id = "2147815377"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/api/uploads/postmap" ascii //weight: 1
        $x_1_2 = "getSmsInPhone has executed" ascii //weight: 1
        $x_1_3 = "getAllContacts" ascii //weight: 1
        $x_1_4 = "SMS_URI_ALL" ascii //weight: 1
        $x_1_5 = "uploadGs" ascii //weight: 1
        $x_1_6 = "/api/uploads/photo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsSpy_J_2147817661_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsSpy.J!MTB"
        threat_id = "2147817661"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/phone2/stop/activity/MainActivity" ascii //weight: 1
        $x_1_2 = "content://sms/100" ascii //weight: 1
        $x_1_3 = "has_send_phone_info" ascii //weight: 1
        $x_1_4 = "sendTextMessage" ascii //weight: 1
        $x_1_5 = "has_send_contacts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsSpy_K_2147829703_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsSpy.K!MTB"
        threat_id = "2147829703"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "smsbomber" ascii //weight: 1
        $x_1_2 = "com/drnull/fcm/smsReceiver" ascii //weight: 1
        $x_1_3 = "hideall" ascii //weight: 1
        $x_1_4 = "POST_NOTOFOCATIONS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsSpy_K_2147829703_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsSpy.K!MTB"
        threat_id = "2147829703"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.aograph.android.agent" ascii //weight: 1
        $x_1_2 = "Fake Arch" ascii //weight: 1
        $x_1_3 = "getContacts" ascii //weight: 1
        $x_1_4 = "getRunning_packages" ascii //weight: 1
        $x_1_5 = "getMessage" ascii //weight: 1
        $x_1_6 = "installNetworkMonitor" ascii //weight: 1
        $x_1_7 = "addLocationListener" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsSpy_N_2147923343_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsSpy.N!MTB"
        threat_id = "2147923343"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/Dragon/convert" ascii //weight: 1
        $x_1_2 = "smsfaory" ascii //weight: 1
        $x_1_3 = "ArabWareSMS" ascii //weight: 1
        $x_1_4 = "smsfawry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsSpy_P_2147923345_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsSpy.P!MTB"
        threat_id = "2147923345"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/ariashirazi/instabrowser" ascii //weight: 1
        $x_1_2 = "?device-info=" ascii //weight: 1
        $x_1_3 = "NurAlam4" ascii //weight: 1
        $x_1_4 = "url opened :" ascii //weight: 1
        $x_1_5 = "sendSmsToServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_SmsSpy_Q_2147923347_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsSpy.Q!MTB"
        threat_id = "2147923347"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/dhruv/smsrecevier" ascii //weight: 1
        $x_1_2 = "Exception smsReceiver" ascii //weight: 1
        $x_1_3 = "senderNum:" ascii //weight: 1
        $x_1_4 = "startupOnBootUpReceiver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsSpy_R_2147925720_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsSpy.R!MTB"
        threat_id = "2147925720"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {35 01 3c 00 46 02 0c 01 70 30 d2 ef 2a 0b 0c 02 38 02 31 00 6e 10 9c 08 02 00 0c 03 6e 10 9b 08 02 00 0c 07 22 02 d8 15 1a 04 ?? ?? 70 20 8b ae 42 00 6e 20 94 ae 32 00 1a 03 95 06 6e 20 94 ae 32 00 6e 20 94 ae 72 00 6e 10 a4 ae 02 00 0c 02 1a 03 ?? 5c 71 20 b2 09 23 00 71 00 97 08 00 00 0c 04 12 08 12 09 1a 05 ?? 14 12 06 74 06 98 08 04 00 d8 01 01 01 28 c5}  //weight: 1, accuracy: Low
        $x_1_2 = {71 00 97 08 00 00 0c 00 12 04 12 05 12 02 07 71 07 83 74 06 98 08 00 00 22 08 d8 15 1a 00 ?? 27 70 20 8b ae 08 00 6e 20 94 ae 78 00 6e 10 a4 ae 08 00 0c 07 12 08 71 30 03 13 76 08 0c 07 6e 10 04 13 07 00 0e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsSpy_S_2147926664_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsSpy.S!MTB"
        threat_id = "2147926664"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "com/kunge/zhitongcar" ascii //weight: 1
        $x_1_2 = {0b 10 00 6e 20 ?? 0b 10 00 6e 20 ?? 0b 10 00 6e 20 ?? 0b 10 00 22 00 ff 0f 70 10 ?? 5d 00 00 6e 20 ?? 0b 04 00 1a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsSpy_Y_2147943675_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsSpy.Y!MTB"
        threat_id = "2147943675"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 06 47 10 00 00 54 01 ac 0e 38 01 0b 00 63 02 9c 0e 39 02 07 00 54 11 22 0e 6e 10 bb 25 01 00}  //weight: 1, accuracy: High
        $x_1_2 = {70 10 26 26 01 00 0c 00 54 00 e1 0e 54 00 6d 00 1f 00 65 01 6e 20 27 07 20 00 0c 02 6f 20 56 10 21 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

