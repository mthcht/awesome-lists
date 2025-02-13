rule TrojanSpy_AndroidOS_SoumniBot_A_2147910827_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SoumniBot.A!MTB"
        threat_id = "2147910827"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SoumniBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "send sms phoneNumber" ascii //weight: 1
        $x_1_2 = "send sms message" ascii //weight: 1
        $x_1_3 = "app@phone1-spy.com" ascii //weight: 1
        $x_1_4 = "/mqtt" ascii //weight: 1
        $x_1_5 = "mainsite" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SoumniBot_B_2147924402_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SoumniBot.B!MTB"
        threat_id = "2147924402"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SoumniBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 00 22 00 ?? 11 70 10 ?? ?? 00 00 62 01 ?? 4b 6e 10 ?? ?? 01 00 0c 02 6e 10 ?? ?? 01 00 0c 01 6e 30 ?? ?? 20 01 0c 00 22 01 ?? ?? 70 10 ?? ?? 01 00 6e 20 ?? ?? 10 00}  //weight: 1, accuracy: Low
        $x_1_2 = {08 00 1a 00 ?? ?? 71 20 ?? ?? 08 00 0a 00 39 00 b3 00 1a 00 ?? 5d 71 10 ?? ?? 00 00 0c 02 6e 10 ?? ?? 08 00 0c 01 12 03 12 04 12 05 12 06 74 06 ?? ?? 01 00 0c 00 38 00 9f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SoumniBot_D_2147924403_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SoumniBot.D!MTB"
        threat_id = "2147924403"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SoumniBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "com/douyin/softwareapp/MainActivity" ascii //weight: 1
        $x_1_2 = {70 10 9e 05 03 00 22 00 f1 11 70 10 3d 87 00 00 62 01 ?? 4b 6e 10 08 4b 01 00 0c 02 6e 10 09 4b 01 00 0c 01 6e 30 9b 87 20 01 0c 00 22 01 19 16 70 10 12 ac 01 00 6e 20 70 87 10 00 0c 00 6e 10 42 87 00 00 0c 00 5b 30 ?? 26 22 00 93 01 71 00 00 0a 00 00 0c 01 70 20 d9 09 10 00 5b 30 ?? 26 22 00 93 1c 70 20 fc dc 30 00 5b 30 ?? 26}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SoumniBot_E_2147924404_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SoumniBot.E!MTB"
        threat_id = "2147924404"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SoumniBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/proc/post/MainActivity" ascii //weight: 1
        $x_1_2 = "INIT SENS_SMS_VAL" ascii //weight: 1
        $x_1_3 = "SendTimeDiffAlarm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SoumniBot_F_2147924405_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SoumniBot.F!MTB"
        threat_id = "2147924405"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SoumniBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/alpras/manager" ascii //weight: 1
        $x_1_2 = "PHONE_SEND_SMS_DATE" ascii //weight: 1
        $x_1_3 = "PHONE_DIFF_WITH_SERVER" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

