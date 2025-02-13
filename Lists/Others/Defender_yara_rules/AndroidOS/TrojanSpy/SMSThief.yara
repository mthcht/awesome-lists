rule TrojanSpy_AndroidOS_SMSThief_O_2147842304_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SMSThief.O!MTB"
        threat_id = "2147842304"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SMSThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SmsReceiver" ascii //weight: 1
        $x_1_2 = "getDisplayOriginatingAddress" ascii //weight: 1
        $x_1_3 = "bot_id_key" ascii //weight: 1
        $x_1_4 = "android.intent.action.MAIN" ascii //weight: 1
        $x_1_5 = "android.intent.category.LAUNCHER" ascii //weight: 1
        $x_10_6 = {0a 01 38 01 13 00 72 10 ?? ?? 07 00 0c 01 07 14 1f 04 ?? ?? 1a 03 ?? ?? 08 01 14 00 08 02 15 00 76 06 ?? ?? 01 00 28 ea 1a 09 ?? ?? 08 07 14 00 08 08 15 00 07 b1 07 5b 07 c2 07 6c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_SMSThief_AT_2147846765_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SMSThief.AT!MTB"
        threat_id = "2147846765"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SMSThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "telegram.org/bot6" ascii //weight: 1
        $x_1_2 = "com/example/myapplicatio" ascii //weight: 1
        $x_1_3 = "/ReceiveSms" ascii //weight: 1
        $x_1_4 = "websettingku" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SMSThief_AY_2147901528_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SMSThief.AY!MTB"
        threat_id = "2147901528"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SMSThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SendSMS" ascii //weight: 1
        $x_1_2 = "websettingku" ascii //weight: 1
        $x_1_3 = "ReceiveSms" ascii //weight: 1
        $x_1_4 = "sendMessage?parse_mode=markdown&chat_id=" ascii //weight: 1
        $x_1_5 = "com.example.myapplicatioo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

