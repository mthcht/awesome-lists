rule Trojan_Win32_CobaltLoader_SK_2147753758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltLoader.SK!MTB"
        threat_id = "2147753758"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 4d fc 53 51 56 57 50 ff 15 ?? ?? 00 10 85 c0 74 1c 33 c0 39 5d fc 76 0a 80 34 38 ?? 40 3b 45 fc 72 f6 ff 75 f8 ff 15 ?? ?? 00 10 ff d7}  //weight: 2, accuracy: Low
        $x_2_2 = {55 8b ec 51 51 53 56 57 6a 04 be ?? ?? 10 00 68 00 10 00 00 33 db 56 53 ff 15 ?? ?? 00 10 8b f8 3b fb 74 4d 53 53 6a 03 53 6a 01 68 00 00 00 80 68 ?? ?? 00 10 ff 15 ?? ?? 00 10 83 f8 ff 89 45 f8 74 2e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltLoader_SL_2147753763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltLoader.SL!MTB"
        threat_id = "2147753763"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "CIA-Don't analyze!!AT28!!" ascii //weight: 5
        $x_1_2 = "CIA.AT28" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltLoader_A_2147776642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltLoader.A"
        threat_id = "2147776642"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6f 70 65 72 61 5f 62 72 6f 77 73 65 72 2e 64 6c 6c 00}  //weight: 2, accuracy: High
        $x_2_2 = {6f 70 65 72 61 5f 62 72 6f 77 73 65 72 2e 70 6e 67 00}  //weight: 2, accuracy: High
        $x_3_3 = {33 c9 c7 85 e4 fd ff ff ?? ?? ?? ?? 85 f6 7e 1c 0f 1f 84 00 00 00 00 00 8b c1 83 e0 03 8a 84 05 e4 fd ff ff 30 04 39 41 3b ce}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

