rule Trojan_Win64_ZooFang_B_2147956899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZooFang.B!dha"
        threat_id = "2147956899"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZooFang"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MS_Office_locker_image_s" wide //weight: 1
        $x_1_2 = "msOfficeLocker__w" wide //weight: 1
        $x_1_3 = "prnfldr.dll" ascii //weight: 1
        $x_1_4 = "1&:18gfz088T" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_ZooFang_C_2147956900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZooFang.C!dha"
        threat_id = "2147956900"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZooFang"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 07 0f b6 c8 48 8b c3 48 83 7b 18 08 72 03 48 8b 03 [0-21] 32 07 0f b6 c8 48 8b c3 48 83 7b 18 08 72 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ZooFang_D_2147956901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZooFang.D!dha"
        threat_id = "2147956901"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZooFang"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be 0f 00 00 00 44 8b c6 33 d2 48 8d 4d ?? e8 ?? ?? ?? ?? 33 d2 48 8d 1d ?? ?? ?? ?? 8a 8c 1a ?? ?? ?? ?? 80 f1 ?? 48 8d 45 ?? 48 39 75}  //weight: 1, accuracy: Low
        $x_1_2 = {44 0f b6 44 08 ?? 41 80 f0 ?? 44 88 44 02 ?? 48 83 c0 02 0f b6 54 08 ?? 48 83 7d ?? 10 49 89 f0 72 ?? 4c 8b 45 ?? 80 f2 ?? 41 88 14 00 48 83 f8 10}  //weight: 1, accuracy: Low
        $x_10_3 = "stobject.dll" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

