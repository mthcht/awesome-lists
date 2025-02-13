rule TrojanDownloader_Win32_Dold_A_2147656676_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dold.A"
        threat_id = "2147656676"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dold"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b7 fb 8b 55 00 0f b6 54 3a ff 0f b7 ce c1 e9 08 32 d1 88 54 38 ff 8b 04 24 0f b6 44 38 ff 66 03 f0 66 0f af 35 ?? ?? ?? ?? 66 03 35 ?? ?? ?? ?? 43 66 ff 4c 24 04 75 c0}  //weight: 2, accuracy: Low
        $x_1_2 = "oJ3FkG0ajooPPlttNTk8F/2Wk+BZmju+yC" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Dold_C_2147658328_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dold.C"
        threat_id = "2147658328"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dold"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {e9 3e e2 f9 ff eb e8 5f 5e 5b 8b e5 5d c3 00 ff ff ff ff 06 00 00 00 49 26 43 48 4b 3d}  //weight: 5, accuracy: High
        $x_2_2 = {83 7e 1c 00 74 53 6a 06 6a 01 6a 02 e8 ?? ?? ?? ?? 89 46 08 66 c7 46 0c 02 00 0f b7 45 fc}  //weight: 2, accuracy: Low
        $x_1_3 = {8b 45 fc 80 78 5b 00 74 3d 8b 45 fc 8b 40 44 80 b8 73 02 00 00 01 74 09 80 3d 5c 16 47 00 01 75 1e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

