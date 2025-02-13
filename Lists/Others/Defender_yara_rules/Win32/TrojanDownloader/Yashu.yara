rule TrojanDownloader_Win32_Yashu_A_2147641899_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Yashu.A"
        threat_id = "2147641899"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Yashu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "del.php?varf=" wide //weight: 1
        $x_1_2 = "del.php?vard=" wide //weight: 1
        $x_2_3 = "\\sing.reg" wide //weight: 2
        $x_2_4 = "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon]" wide //weight: 2
        $x_2_5 = {44 6f 77 6e 6c 00 00 00 79 61 73 68 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

