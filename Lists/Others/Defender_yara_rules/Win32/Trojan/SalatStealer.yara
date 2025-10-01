rule Trojan_Win32_SalatStealer_KAT_2147946544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.KAT!MTB"
        threat_id = "2147946544"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.decryptData" ascii //weight: 1
        $x_1_2 = "findLsassProcess" ascii //weight: 1
        $x_1_3 = "shellCommand" ascii //weight: 1
        $x_1_4 = "sendScreen" ascii //weight: 1
        $x_1_5 = "runKeylogger" ascii //weight: 1
        $x_1_6 = "salat/main" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SalatStealer_NV_2147953702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.NV!MTB"
        threat_id = "2147953702"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {21 d3 09 eb 84 db 75 06 31 d2 31 db eb 14 e8 16 6f 06 00 8b 04 24 8b 4c 24 04 89 ca 89 c3 8b 44 24 3c 89 5c 24 18 89 54 24 1c 8d 48 30}  //weight: 2, accuracy: High
        $x_1_2 = {ff 74 20 e8 7c 7a 06 00 89 0f 8b 58 08 89 5f 04 89 47 08 8b 59 04 89 5f 0c 8b 5e 2c 89 5f 10 8b 5c 24 18 89 48 08 89 41 04 89 46 2c eb 30 8b 0d 60 4a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

