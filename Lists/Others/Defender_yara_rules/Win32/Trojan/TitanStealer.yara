rule Trojan_Win32_TitanStealer_RDA_2147837539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TitanStealer.RDA!MTB"
        threat_id = "2147837539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TitanStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b f0 8b c6 c1 e8 05 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 0c 8b 45 ec 01 45 0c 8b c6 c1 e0 04 03 45 e8 03 de 33 c3 33 45 0c 50}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TitanStealer_PA_2147839625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TitanStealer.PA!MTB"
        threat_id = "2147839625"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TitanStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Go build ID:" ascii //weight: 1
        $x_2_2 = {5f 2f 43 5f 2f 55 73 65 72 73 2f [0-21] 2f 44 65 73 6b 74 6f 70 2f 73 74 65 61 6c 65 72 5f 76}  //weight: 2, accuracy: Low
        $x_2_3 = "77.73.133.88" ascii //weight: 2
        $x_3_4 = {01 d6 89 f0 c1 fe 1f c1 ee 17 01 c6 c1 fe 09 c1 e6 09 29 f0 89 05 ?? ?? ?? ?? 01 d3 8b 44 24 ?? 89 ea 39 da 7e}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TitanStealer_CCEW_2147897892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TitanStealer.CCEW!MTB"
        threat_id = "2147897892"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TitanStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 08 03 55 fc 0f b6 02 89 45 f8 8b 4d 08 03 4d fc 0f b6 11 33 55 f4 8b 45 08 03 45 fc 88 10 8b 4d f8 89 4d f4 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

