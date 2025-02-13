rule Trojan_Win64_Regin_D_2147692608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Regin.D!dha"
        threat_id = "2147692608"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Regin"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 00 44 77 48 8d 50 d8 80 00 44 7b c7 40 d8 10 00 00 00 80 00 44 82 c7 40 e0 07 00 00 00 80 00 44 89 44 89 40 ec 80 00 44 8d c7 40 f0 b8 0b 00 00 80 00 44 94 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {80 00 44 c3 33 d2 80 00 44 c5 44 8b c3 80 00 44 c8 8d 4a 05 80 00 44 cb e8 ?? ?? ?? ?? 80 00 44 d0 b9 04 00 00 00 80 00 44 d5 eb}  //weight: 1, accuracy: Low
        $x_1_3 = {80 00 44 d7 33 d2 80 00 44 d9 44 8b c3 80 00 44 dc 8d 4a 06 80 00 44 df e8 ?? ?? ?? ?? 80 00 44 e4 b9 07 00 00 00 80 00 44 e9 eb}  //weight: 1, accuracy: Low
        $x_1_4 = {80 00 44 eb 33 d2 80 00 44 ed 44 8b c3 80 00 44 f0 8d 4a 03 80 00 44 f3 e8 ?? ?? ?? ?? 80 00 44 f8 48 8d 0d ?? ?? ?? ?? 80 00 44 ff 44 8b c3 80 00 45 02 33 d2}  //weight: 1, accuracy: Low
        $x_1_5 = {80 00 46 2f bb 01 00 00 00 80 00 46 34 33 d2 80 00 46 36 8d 4b 01 80 00 46 39 44 8b c3 80 00 46 3c e8 ?? ?? ?? ?? 80 00 46 41 8d 4b 03 80 00 46 44 45 33 c0 80 00 46 47 33 d2 80 00 46 49 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win64_Regin_B_2147696092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Regin.B!dha"
        threat_id = "2147696092"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Regin"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 3b fb 73 1d 8b c7 41 8d 0c 28 ff c5 4a 8d 14 08 83 e0 07 ff c7 8a 04 30 32 c1 30 02 83 fd 08 72 de}  //weight: 1, accuracy: High
        $x_1_2 = "\\\\.\\PhysicalDrive%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

