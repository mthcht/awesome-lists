rule Trojan_MSIL_SapphireStealer_ASH_2147890050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SapphireStealer.ASH!MTB"
        threat_id = "2147890050"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SapphireStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 2d 01 2a 72 ?? 01 00 70 73 ?? 00 00 0a 25 72 ?? 01 00 70 06 72 ?? 01 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 25 16}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SapphireStealer_ASH_2147890050_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SapphireStealer.ASH!MTB"
        threat_id = "2147890050"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SapphireStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {18 5a 1f 16 58 0a 2b 43 06 09 5d 13 05 06 11 07 5d 13 0b 07 11 05 91 13 0c 11 04 11 0b 6f ?? ?? ?? 0a 13 0d 07 06 17 58 09 5d 91 13 0e 11 0c 11 0d 11 0e 28 ?? ?? ?? 06 13 0f 07 11 05 11 0f 20 00 01 00 00 5d d2 9c 06 17 59 0a 06 16 fe 04 16 fe 01 13 10 11 10 2d b0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SapphireStealer_ZQ_2147904964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SapphireStealer.ZQ!MTB"
        threat_id = "2147904964"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SapphireStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sapphire\\obj\\" ascii //weight: 1
        $x_1_2 = "[ERROR_GETSECRETKEY_METHOD]" ascii //weight: 1
        $x_1_3 = "[ERROR_CANT_GET_PASSWORD]" ascii //weight: 1
        $x_1_4 = "Telegram+<SendLogs>d__0" ascii //weight: 1
        $x_1_5 = "[ERROR] can't create work directory" ascii //weight: 1
        $x_1_6 = "Yandex\\YandexBrowser\\User Data" ascii //weight: 1
        $x_1_7 = "BraveSoftware\\Brave-Browser\\User Data" ascii //weight: 1
        $x_1_8 = "cookies.json" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

