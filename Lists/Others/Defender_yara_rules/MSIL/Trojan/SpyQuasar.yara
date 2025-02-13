rule Trojan_MSIL_SpyQuasar_MA_2147796702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyQuasar.MA!MTB"
        threat_id = "2147796702"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyQuasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 17 6f 2b ?? ?? 0a 06 17 6f 2c ?? ?? 0a 4f 00 73 24 00 00 0a 0a 06 72 ?? 06 00 70 72 ?? 07 00 70 7e 25 00 00 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 8c 24 00 00 01 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a}  //weight: 1, accuracy: Low
        $x_1_2 = "MD5CryptoServiceProvider" ascii //weight: 1
        $x_1_3 = "GetBytes" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "DownloadString" ascii //weight: 1
        $x_1_6 = "Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyQuasar_MB_2147808842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyQuasar.MB!MTB"
        threat_id = "2147808842"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyQuasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 17 58 0b 07 20 00 01 00 00 5d 0b 09 11 07 07 94 58 0d 09 20 00 01 00 00 5d 0d 11 07 07 94 13 05 11 07 07 11 07 09 94 9e 11 07 09 11 05 9e 11 07 11 07 07 94 11 07 09 94 58 20 00 01 00 00 5d 94 13 04 11 08 08 02 08 91 11 04 61 d2 9c 08 17 58 0c 08 02 8e 69 32}  //weight: 1, accuracy: High
        $x_1_2 = "Bitcoin" ascii //weight: 1
        $x_1_3 = "Sleep" ascii //weight: 1
        $x_1_4 = "Flag1" ascii //weight: 1
        $x_1_5 = "GetBytes" ascii //weight: 1
        $x_1_6 = "DownloadString" ascii //weight: 1
        $x_1_7 = "DebuggableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

