rule TrojanDownloader_Win32_Claragit_A_2147622746_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Claragit.A"
        threat_id = "2147622746"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Claragit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 00 83 e1 03 6a 00 6a 00 68 ?? ?? ?? ?? f3 aa ff 15 ?? ?? ?? ?? 8b f8 85 ff 74 48 8b 44 24 14 56 6a 00 68 00 00 00 80}  //weight: 2, accuracy: Low
        $x_2_2 = {75 30 8d 44 24 04 50 ff 15 ?? ?? ?? ?? 8b 54 24 00 8d 4c 24 04 50 51 6a 01 6a 00}  //weight: 2, accuracy: Low
        $x_1_3 = ".com/suc.php" ascii //weight: 1
        $x_1_4 = "svchostw.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

