rule TrojanDownloader_Win32_Skider_A_2147605142_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Skider.A"
        threat_id = "2147605142"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Skider"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 14 01 00 00 00 c6 44 24 13 00 e8 ?? ?? 00 00 8b 84 24 ?? ?? 00 00 8d 4c 24 08 50 e8 ?? ?? 00 00 68 ?? ?? ?? ?? 8d 4c 24 0c e8 ?? ?? 00 00 68 ?? ?? ?? ?? 8d 4c 24 0c e8 ?? ?? 00 00 8b b4 24 ?? ?? 00 00 8d 4c 24 08 56 e8 ?? ?? 00 00 68 ?? ?? ?? ?? 8d 4c 24 0c e8 ?? ?? 00 00 8d 4c 24 14 e8 ?? ?? 00 00 8d 4c 24 2c}  //weight: 1, accuracy: Low
        $x_1_2 = "http://update.diskster.com/DB/" ascii //weight: 1
        $x_1_3 = "C:\\Program Files\\Diskster\\Data\\" ascii //weight: 1
        $x_1_4 = "Disk1004.ico" ascii //weight: 1
        $x_1_5 = "disk1004.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

