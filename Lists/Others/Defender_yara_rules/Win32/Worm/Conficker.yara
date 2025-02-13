rule Worm_Win32_Conficker_A_2147616597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Conficker.gen!A"
        threat_id = "2147616597"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Conficker"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 21 a2 90 00 2e 64 6c 6c 13 ff e7 ff cd 5c 47 6c 6f 62 61 6c 5c 25 75 2d 25 75 42 e9 4c 30 39}  //weight: 2, accuracy: High
        $x_1_2 = {59 59 85 c0 75 11 ff 75 08 ff 15 ?? ?? ?? ?? 59 3d c8 00 00 00 76 16 83 4d fc ff 6a 57}  //weight: 1, accuracy: Low
        $x_1_3 = {76 18 8b 06 03 c7 80 30 ?? 8d 45 ?? 50 47 e8 ?? ?? ?? ?? 03 c3 3b f8 59 72 e8 8b 06}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 0e 8d 87 ?? ?? 00 00 68 ?? ?? ?? ?? 50 e8 ?? ?? 00 00 8d 87 ?? ?? 00 00 66 c7 00 41 00}  //weight: 1, accuracy: Low
        $x_1_5 = {c6 46 40 eb c6 46 41 02 c6 46 44 eb c6 46 45 58 eb 3a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Conficker_B_2147618124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Conficker.B"
        threat_id = "2147618124"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Conficker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 31 89 45 ?? 89 55 ?? ff 75 ?? ?? 8b 55 ?? 2b c0 ff 25}  //weight: 1, accuracy: Low
        $x_1_2 = {2b f6 0b c2 09 f1 a3 ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 58 50 68 00 ?? ?? ?? ff 15 ?? ?? ?? ?? 6a ?? a3 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? a3 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 0f 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Conficker_B_2147618124_1
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Conficker.B"
        threat_id = "2147618124"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Conficker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 bc 50 ff 15 ?? ?? ?? ?? 66 81 7d bc d9 07 77 11 0f 85 da 01 00 00 66 83 7d be 01 0f 82 cf 01 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "http://%s/search?q=%d" ascii //weight: 1
        $x_1_3 = {ff 53 4d 42 72 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 5c 02 00 00 00 00 00 0c 00 02 4e 54 20 4c 4d 20 30 2e 31 32 00 00 00 00 00 49 ff 53 4d 42 73 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 5c 02 00 00 00 00 0d ff 00 00 00 ff ff 02 00 5c 02 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 0b 00 00 00 4d 53 00 43 4c 49 45 4e 54 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Worm_Win32_Conficker_D_2147618296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Conficker.D"
        threat_id = "2147618296"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Conficker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {59 33 d2 6a 29 59 f7 f1 83 c2 0a 69 d2 e8 03 00 00 89 95 ?? ?? ff ff 3b d6 76 09 2b d6 52 ff 15}  //weight: 10, accuracy: Low
        $x_1_2 = "%SystemRoot%\\system32\\svchost.exe -k" wide //weight: 1
        $x_1_3 = "rundll32.exe \"%s\",%S" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Conficker_E_2147623658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Conficker.E"
        threat_id = "2147623658"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Conficker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 68 02 02 00 00 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 6a 1e 99 59 f7 f9 83 c2 05 69 d2 60 ea 00 00 52 ff d7 6a 63 e8 55 8b ec 6a ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Conficker_E_2147623662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Conficker.E"
        threat_id = "2147623662"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Conficker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d9 07 72 19 75 10 66 83 7d ?? ?? 72 10 75 07 66 83 7d ?? ?? 72 07 e8 55 8b ec 81 ec 08 01 00 00 a1 ?? ?? ?? ?? 33 c5 89 45 fc 68 04 01 00 00 8d 85 f8 fe ff ff 50 6a 00 ff 15 ?? ?? ?? ?? 6a 04 6a 00 8d 85 f8 fe ff ff 50 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

