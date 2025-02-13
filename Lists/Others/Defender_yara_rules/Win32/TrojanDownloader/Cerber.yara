rule TrojanDownloader_Win32_Cerber_A_2147710747_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cerber.A!bit"
        threat_id = "2147710747"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b3 0d 8a 06 3c 6d 7f 22 0f be c0 50 e8 ?? ?? 00 00 59 85 c0 74 14 0f be 06 50 e8 ?? ?? 00 00 59 85 c0 74 06 8a 06 02 c3 eb 6e 8a 06 3c 4d 7f 1c 0f be c0 50 e8 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_2_2 = {75 67 67 63 3a 2f 2f 32 32 30 2e 31 38 31 2e 38 37 2e 38 30 2f [0-16] 2e 72 6b 72}  //weight: 2, accuracy: Low
        $x_1_3 = {53 53 6a 03 53 6a 03 53 68 1c 39 40 00 c7 45 64 ?? ?? 40 00 c7 45 68 ?? ?? 40 00 c7 45 6c ?? ?? 40 00 89 5d 70 ff 15 ?? ?? 40 00 8b f8 83 ff ff 0f 84 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {8d 45 74 50 56 8d 85 58 ff ff ff 50 6a 0c 8d 45 58 50 68 00 14 2d 00 57 ff 15 ?? ?? 40 00 85 c0 74}  //weight: 1, accuracy: Low
        $x_1_5 = {56 61 67 72 65 61 72 67 45 72 6e 71 53 76 79 72 00}  //weight: 1, accuracy: High
        $x_1_6 = {78 72 65 61 72 79 33 32 00}  //weight: 1, accuracy: High
        $x_1_7 = {50 65 72 6e 67 72 43 65 62 70 72 66 66 4e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Cerber_A_2147711326_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cerber.A"
        threat_id = "2147711326"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "uggc://" ascii //weight: 10
        $x_10_2 = {2e 72 6b 72 00}  //weight: 10, accuracy: High
        $x_10_3 = "jvavarg" ascii //weight: 10
        $x_10_4 = "TrgGrzcCnguN" ascii //weight: 10
        $x_1_5 = "windrv32.exe" ascii //weight: 1
        $x_1_6 = "winmgr.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

