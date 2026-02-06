rule Trojan_Win32_FatBeehive_C_2147957552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FatBeehive.C!dha"
        threat_id = "2147957552"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FatBeehive"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 8b c1 f7 f6 0f b6 c1 03 55 [0-1] 6b c0 55 32 02 88 04 0f 41 83 f9 20}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 44 0f ff 02 04 0f 34 [0-1] 88 04 0f 41 83 f9 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FatBeehive_E_2147957675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FatBeehive.E!dha"
        threat_id = "2147957675"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FatBeehive"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 01 84 c0 75 03 8b c2 [0-1] 0f be c0 33 c2 69 d0 a4 61 13 03 41}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 3c b0 8a 04 1f 03 fb 84 c0 75 [0-1] b8 1a 54 32 24 eb 1c 0f be c0 8d 4f 01 35 1a 54 32 24 69 d0 a4 61 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FatBeehive_F_2147962523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FatBeehive.F!dha"
        threat_id = "2147962523"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FatBeehive"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 68 65 63 ?? 67 20 20}  //weight: 1, accuracy: Low
        $x_1_2 = {66 89 84 24 ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 48 89 84 24 ?? ?? ?? ?? 0f 28 05 ?? ?? ?? ?? 0f 29 84 24 ?? ?? ?? ?? 0f 28 05}  //weight: 1, accuracy: Low
        $x_1_3 = {4e 74 43 72 65 61 74 65 ?? 68 72 65 61 64 45 78}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

