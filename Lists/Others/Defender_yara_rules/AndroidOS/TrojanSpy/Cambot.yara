rule TrojanSpy_AndroidOS_Cambot_YA_2147756743_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Cambot.YA!MTB"
        threat_id = "2147756743"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Cambot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f [0-21] 2f 70 72 69 76 61 74 65 2f 61 64 64 5f 6c 6f 67 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_2 = "anu_bispulo.app" ascii //weight: 1
        $x_1_3 = "SmsMessage.createFromPdu" ascii //weight: 1
        $x_1_4 = "SetJavaScriptEnabled" ascii //weight: 1
        $x_1_5 = "_CMOXCdVTJREB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_AndroidOS_Cambot_A_2147783395_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Cambot.A"
        threat_id = "2147783395"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Cambot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3a 00 1c 00 6e 20 ?? ?? 14 00 0a 00 d8 03 01 ff df 00 00 0d 8e 00 50 00 02 01 3a 03 0f 00 d8 00 03 ff 6e 20 ?? ?? 34 00 0a 01 df 01 01 66 8e 11 50 01 02 03 01 01 28 e5}  //weight: 2, accuracy: Low
        $x_1_2 = "/private/add_log.php" ascii //weight: 1
        $x_1_3 = "/resiverboot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

