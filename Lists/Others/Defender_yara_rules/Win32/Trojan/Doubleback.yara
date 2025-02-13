rule Trojan_Win32_Doubleback_RPY_2147842827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doubleback.RPY!MTB"
        threat_id = "2147842827"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doubleback"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 f2 48 7f cc d6 7f bb 73 b9 8b 85 18 ff ff ff 33 d2 f7 75 14 8b 45 10 0f b6 0c 10 8b 55 08 03 95 18 ff ff ff 0f b6 02 2b c1 8b 4d 08 03 8d 18 ff ff ff 88 01 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Doubleback_RPX_2147843171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doubleback.RPX!MTB"
        threat_id = "2147843171"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doubleback"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 75 c4 50 89 e6 89 75 c8 50 89 e6 89 75 cc 50 89 e6 89 75 d0 50 89 e6 89 75 d4 50 89 e6 89 75 d8 8b 75 9c c7 06 00 00 00 00 8b 75 84 89 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

