rule TrojanDownloader_Win32_Truebot_A_2147724324_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Truebot.A"
        threat_id = "2147724324"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Truebot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 3e 66 75 ?? 80 7e 01 61 75 ?? 80 7e 02 6c}  //weight: 1, accuracy: Low
        $x_1_2 = {80 7e 02 45 75 ?? 80 7e 03 4c 03 00 44 75}  //weight: 1, accuracy: Low
        $x_1_3 = {80 3e 7c 0f 85 ?? ?? ?? ?? ?? [0-2] 68 0f 85 ?? ?? ?? ?? 80 7e 02 74 0f 85 ?? ?? ?? ?? 80 7e 03 74 0f 85 ?? ?? ?? ?? 80 7e 04 70 0f 85}  //weight: 1, accuracy: Low
        $x_1_4 = {25 73 67 65 74 2e 70 68 70 3f 6e 61 6d 65 3d 25 78 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

