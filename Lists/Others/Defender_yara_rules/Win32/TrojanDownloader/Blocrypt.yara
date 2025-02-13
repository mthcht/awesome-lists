rule TrojanDownloader_Win32_Blocrypt_A_2147718756_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Blocrypt.A!bit"
        threat_id = "2147718756"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Blocrypt"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 05 50 ec 47 00 8b 1d ?? ?? ?? ?? 33 c6 33 c1 8a ?? ?? ?? ?? ?? 41 81 f9 ?? ?? ?? ?? 88 14 18 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {99 59 f7 f9 85 d2 74 17 66 81 3d ?? ?? ?? ?? ?? ?? 75 3b a1 ?? ?? ?? ?? 03 c3 80 30 ?? eb}  //weight: 1, accuracy: Low
        $x_1_3 = {ff d5 8b c8 8b 44 24 ?? 33 d2 f7 f1 2c ?? 30 06 43 81 fb ?? ?? ?? ?? 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Blocrypt_B_2147719012_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Blocrypt.B!bit"
        threat_id = "2147719012"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Blocrypt"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SELECT * FROM Win32_BaseBoard" wide //weight: 1
        $x_1_2 = "vvyomm" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\AdVPN" wide //weight: 1
        $x_1_4 = {8b c1 33 d2 f7 35 ?? ?? ?? ?? 41 8a 82 ?? ?? ?? ?? 2a 44 0b ff 88 44 0b ff 3b 4d 0c 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

