rule TrojanSpy_AndroidOS_SMSSpy_A_2147783601_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SMSSpy.A!MTB"
        threat_id = "2147783601"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SMSSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/getSmsSend.php" ascii //weight: 1
        $x_1_2 = "smsapi.hejupay.com" ascii //weight: 1
        $x_1_3 = "UpaySms" ascii //weight: 1
        $x_1_4 = "SENT_SMS_ACTION_UPAY" ascii //weight: 1
        $x_1_5 = "SendNumber_" ascii //weight: 1
        $x_1_6 = "verifySmsReSendNum" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SMSSpy_B_2147788229_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SMSSpy.B!MTB"
        threat_id = "2147788229"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SMSSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "alpha virus has installed to victiom phone" ascii //weight: 1
        $x_1_2 = "_tokenbot" ascii //weight: 1
        $x_1_3 = "/api.telegram.org/bot" ascii //weight: 1
        $x_1_4 = "/sendmessage" ascii //weight: 1
        $x_1_5 = "background runned" ascii //weight: 1
        $x_1_6 = "SMSInterceptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SMSSpy_C_2147789237_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SMSSpy.C!MTB"
        threat_id = "2147789237"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SMSSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "const_register_bot" ascii //weight: 1
        $x_1_2 = "setSaveInboxSms" ascii //weight: 1
        $x_1_3 = "Comand send sms id" ascii //weight: 1
        $x_1_4 = "smsControl" ascii //weight: 1
        $x_1_5 = "Set bot id" ascii //weight: 1
        $x_1_6 = "saveCard - getInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SMSSpy_D_2147798596_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SMSSpy.D!MTB"
        threat_id = "2147798596"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SMSSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {21 51 6e 10 ?? ?? 06 00 0a 02 12 00 34 10 08 00 22 00 ?? ?? 70 20 ?? ?? 50 00 11 00 48 03 05 00 94 04 00 02 6e 20 ?? ?? 46 00 0a 04 b7 43 8d 33 4f 03 05 00 d8 00 00 01 28 ea}  //weight: 2, accuracy: Low
        $x_1_2 = "cn/sadsxcds/sadcccc/SmSserver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SMSSpy_E_2147808783_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SMSSpy.E!MTB"
        threat_id = "2147808783"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SMSSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getIncomingMessage" ascii //weight: 1
        $x_1_2 = "/sms.php" ascii //weight: 1
        $x_1_3 = "senderNo" ascii //weight: 1
        $x_1_4 = "ir/iran/pardakht/SMSBroadcastReceiver" ascii //weight: 1
        $x_1_5 = "deleteChat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SMSSpy_F_2147809346_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SMSSpy.F!MTB"
        threat_id = "2147809346"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SMSSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "muapks.online" ascii //weight: 1
        $x_1_2 = "grabsapks.online" ascii //weight: 1
        $x_2_3 = "api_spa24125/api_espanol/api.php?sid=%1$s&sms=%2$s" ascii //weight: 2
        $x_2_4 = {61 70 70 5f 61 62 63 37 37 31 5f 32 73 66 61 63 73 6c 66 66 66 63 73 32 2f [0-48] 5f 38 38 38 61 2f 64 6c 2e 70 68 70}  //weight: 2, accuracy: Low
        $x_1_5 = {63 6f 6d 2f [0-7] 2f [0-21] 2f 4d 79 52 65 63 [0-2] 76 65 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_SMSSpy_I_2147824754_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SMSSpy.I!MTB"
        threat_id = "2147824754"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SMSSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DevAdReceiver" ascii //weight: 1
        $x_1_2 = "sendHttpAddDev" ascii //weight: 1
        $x_1_3 = "mDeleteCallLogHandler" ascii //weight: 1
        $x_1_4 = "sendSMS2Long" ascii //weight: 1
        $x_1_5 = "/soapi/getmsgs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SMSSpy_L_2147835832_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SMSSpy.L!MTB"
        threat_id = "2147835832"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SMSSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "net.trices." ascii //weight: 1
        $x_1_2 = "SmsListner" ascii //weight: 1
        $x_1_3 = "intent.extras!!" ascii //weight: 1
        $x_1_4 = "Received SMS from" ascii //weight: 1
        $x_1_5 = "REQ_CODE_PERMISSION_READ_SMS" ascii //weight: 1
        $x_1_6 = "REQ_CODE_PERMISSION_RECEIVE_SMS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SMSSpy_M_2147836898_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SMSSpy.M"
        threat_id = "2147836898"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SMSSpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tcam/BMess" ascii //weight: 1
        $x_1_2 = "tcam/BSer" ascii //weight: 1
        $x_1_3 = "/click_2/index.php" ascii //weight: 1
        $x_1_4 = "tcam/LoadActiv" ascii //weight: 1
        $x_1_5 = "tcam/RActiv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_SMSSpy_M_2147843535_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SMSSpy.M!MTB"
        threat_id = "2147843535"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SMSSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "bSMSBlockState" ascii //weight: 5
        $x_1_2 = "Preodic" ascii //weight: 1
        $x_1_3 = "prfSettings" ascii //weight: 1
        $x_1_4 = "onStartCommand" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_SMSSpy_O_2147911998_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SMSSpy.O!MTB"
        threat_id = "2147911998"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SMSSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CallMonitor" ascii //weight: 1
        $x_1_2 = "BOT_TOKEN" ascii //weight: 1
        $x_1_3 = "SMSMonitor" ascii //weight: 1
        $x_1_4 = "/sendMessage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SMSSpy_T_2147935652_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SMSSpy.T!MTB"
        threat_id = "2147935652"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SMSSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 20 fe 9f 10 00 0a 02 38 02 14 00 62 02 3b 56 71 00 4f a0 00 00 0b 03 71 20 89 9f 43 00 0c 03 6e 20 d4 a1 32 00 0c 02 6e 30 19 a0 10 02 0c 00}  //weight: 1, accuracy: High
        $x_1_2 = {6e 30 19 a0 21 03 0c 01 62 02 3c 56 71 00 4f a0 00 00 0b 03 71 20 89 9f 43 00 0c 03 6e 20 d4 a1 32 00 0c 02 1a 03 ?? 80 6e 30 19 a0 31 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SMSSpy_U_2147935655_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SMSSpy.U!MTB"
        threat_id = "2147935655"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SMSSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 20 fe 9f 10 00 0a 02 38 02 14 00 62 02 3b 56 71 00 4f a0 00 00 0b 03 71 20 89 9f 43 00 0c 03 6e 20 d4 a1 32 00 0c 02 6e 30 19 a0 10 02 0c 00}  //weight: 1, accuracy: High
        $x_1_2 = {12 00 1a 01 ?? ?? 71 00 4b 07 00 00 0c 02 6e 10 3c 9e 02 00 0c 02 1a 03 ?? ?? 6e 30 19 a0 31 02 0c 01 1a 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

