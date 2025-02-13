rule Trojan_Win32_Delflob_A_2147598761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delflob.A"
        threat_id = "2147598761"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delflob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {49 45 2b 44 45 46 45 4e 44 45 52 00 [0-48] 4b 41 53 50 45 52 53 4b 59 00 [0-80] 4d 43 41 46 45 45 00}  //weight: 10, accuracy: Low
        $x_1_2 = {69 65 64 65 66 65 6e 64 65 72 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_3 = {64 69 76 78 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64}  //weight: 1, accuracy: High
        $x_1_4 = {00 6c 69 76 65 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_5 = "ConvertStringSecurityDescriptorToSecurityDescriptorA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Delflob_I_2147599705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delflob.I"
        threat_id = "2147599705"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delflob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 e8 01 00 00 00 8d 45 ?? 8b 55 fc 8b 4d e8 8a 54 0a ff 8a 4d fb 32 d1 e8 ?? ?? ?? ff 8b 55 ?? 8d 45 f0 e8 ?? ?? ?? ff ff 45 e8 ff 4d ?? 75 d6}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 e8 01 00 00 00 8d 85 ?? ?? ff ff 8b 55 fc 8b 4d e8 8a 54 0a ff 8a 4d fb 32 d1 e8 ?? ?? ?? ff 8b 95 ?? ?? ff ff 8d 45 f0 e8 ?? ?? ?? ff ff 45 e8 ff 4d ?? 75 d0}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 45 e8 01 00 00 00 8d 85 ?? ?? ff ff 8b 55 fc 8b 4d e8 8a 54 0a ff 8a 4d fb 32 d1 e8 ?? ?? ?? ff 8b 95 ?? ?? ff ff 8d 45 f0 e8 ?? ?? ?? ff ff 45 e8 ff 8d ?? ?? ff ff 75 cd}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 45 e8 01 00 00 00 8d 45 ?? 8a 55 fb 8b 4d fc 8b 5d e8 8a 4c 19 ff 32 d1 e8 ?? ?? ?? ff 8b 55 ?? 8d 45 f0 e8 ?? ?? ?? ff ff 45 e8 ff 4d ?? 75 d6}  //weight: 1, accuracy: Low
        $x_1_5 = {c7 45 e8 01 00 00 00 8d 85 ?? ?? ff ff 8b 55 e8 8b 4d fc 4a 85 c9 74 05 3b 51 fc 72 05 e8 ?? ?? ff ff 42 8a 54 11 ff 8a 4d fb 32 d1 e8 ?? ?? ff ff 8b 95 ?? ?? ff ff 8d 45 f0 e8 ?? ?? ff ff ff 45 ?? ff 4d ?? 75 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Delflob_J_2147599706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delflob.J"
        threat_id = "2147599706"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delflob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 8d 45 e0 b9 ?? ?? ?? 00 8b 15 ?? ?? ?? 00 e8 ?? ?? ?? ff 8b 45 e0 e8 ?? ?? ?? ff 50 a1 ?? ?? ?? 00 e8 ?? ?? ?? ff 50 e8 ?? ?? ?? ff c7 05 ?? ?? ?? 00 ?? ?? ?? ?? (81|83) 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delflob_P_2147607932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delflob.P"
        threat_id = "2147607932"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delflob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 e8 01 00 00 00 8d 45 ?? 8b 55 ?? 8b 4d ?? [0-32] 8a ?? ?? ff 8a 4d fb 32 d1 e8 ?? ?? ?? ff 8b 55 ?? 8d 45 f0 e8 ?? ?? ?? ff ff 45 e8 (4b|ff 4d ??) 75 8d 45 ?? 8b 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Delflob_S_2147621254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delflob.S"
        threat_id = "2147621254"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delflob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ListViewMalwaresl" ascii //weight: 2
        $x_2_2 = "act_StartScan" ascii //weight: 2
        $x_2_3 = "act_PauseScan" ascii //weight: 2
        $x_2_4 = "cbScanOnStartup" ascii //weight: 2
        $x_2_5 = "ListViewMalwaresCustomDrawItem" ascii //weight: 2
        $x_2_6 = "/index.php?la=order#1" ascii //weight: 2
        $x_1_7 = "has found %d useless  and UNWANTED files on your computer!" ascii //weight: 1
        $x_1_8 = "critical privacy comromising content" ascii //weight: 1
        $x_1_9 = "medium privacy threats" ascii //weight: 1
        $x_1_10 = "to be junk content of low privacy threats" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            (all of ($x*))
        )
}

