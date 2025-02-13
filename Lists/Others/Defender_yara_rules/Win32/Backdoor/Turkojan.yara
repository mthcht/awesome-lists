rule Backdoor_Win32_Turkojan_A_2147603553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Turkojan.gen!A"
        threat_id = "2147603553"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Turkojan"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Turkojan Server" ascii //weight: 1
        $x_1_2 = {54 75 72 6b 6f 6a 61 6e 20 ?? 2e 30}  //weight: 1, accuracy: Low
        $x_1_3 = "http://www.turkojan.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Turkojan_C_2147603554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Turkojan.C"
        threat_id = "2147603554"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Turkojan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Dosya bulunamad" ascii //weight: 1
        $x_1_2 = "[CAPS LOCK]" ascii //weight: 1
        $x_1_3 = "[Ftp/IE/Firefox/Outlook Passwords]" ascii //weight: 1
        $x_1_4 = "[IM Passwords]" ascii //weight: 1
        $x_1_5 = "WBCAM###" ascii //weight: 1
        $x_1_6 = "NumLock Durumu :" ascii //weight: 1
        $x_10_7 = {8b c0 55 8b ec 6a 00 6a 00 53 56 57 8b d9 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 8d 55 f8 8b c3 e8 ?? ?? ?? ?? 8b 45 f8 8d 55 fc e8 ?? ?? ?? ?? ff 05 ?? ?? ?? ?? 8b 45 fc ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 75 07 c6 05 ?? ?? ?? ?? 01 33 c0 5a 59 59 64 89 10 eb 0a e9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 33 c0 5a 59 59 64 89 10 68 ?? ?? ?? ?? 8d 45 f8 ba 02 00 00 00}  //weight: 10, accuracy: Low
        $x_10_8 = {8b c8 83 e9 05 ba 06 00 00 00 8b 45 e0 e8 ?? ?? ?? ?? 8b 45 c8 8d 55 cc e8 ?? ?? ?? ?? 8b 45 cc ba 64 00 00 00 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 74 5e 68 ?? ?? ?? ?? 8d 55 c8 8b 45 fc e8 ?? ?? ?? ?? ff 75 c8 68 ?? ?? ?? ?? 8d 55 c0 8b 45 fc e8 ?? ?? ?? ?? 8d 45 c0 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 c0 8d 4d c4 8b 45 fc e8 ?? ?? ?? ?? ff 75 c4 68 ?? ?? ?? ?? 8d 45 cc ba 05 00 00 00 e8 ?? ?? ?? ?? 8b 55 cc 8b 45 f8 e8 ?? ?? ?? ?? 8d 45 cc 50 b9 05 00 00 00 ba 01 00 00 00 8b 45 e0 e8 ?? ?? ?? ?? 8b 45 cc ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 0f 85 c0 00 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Turkojan_AI_2147625080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Turkojan.AI"
        threat_id = "2147625080"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Turkojan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 00 44 00 45 00 4e 00 45 00 4d 00 45 00 06 00 44 00 56 00 43 00 4c 00 41 00 4c 00 03 00 45 00 44 00 54 00 0b 00 50 00 41 00 43 00 4b 00 41 00 47 00 45 00 49 00 4e 00 46 00 4f 00 07 00 52 00 4f 00 4f 00 54 00 4b 00 49 00 54 00}  //weight: 1, accuracy: High
        $x_1_2 = {06 00 44 00 56 00 43 00 4c 00 41 00 4c 00 03 00 45 00 44 00 54 00 06 00 4b 00 4c 00 41 00 56 00 59 00 45 00 0b 00 50 00 41 00 43 00 4b 00 41 00 47 00 45 00 49 00 4e 00 46 00 4f 00 07 00 50 00 45 00 4e 00 43 00 45 00 52 00 45 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

