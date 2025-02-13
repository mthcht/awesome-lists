rule TrojanDownloader_Win32_Neglemir_A_2147652291_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Neglemir.A"
        threat_id = "2147652291"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Neglemir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {eb 0c 68 d0 07 00 00 e8 ?? ?? ?? ?? eb ?? 33 c0 5a 59 59 64 89 10 68}  //weight: 2, accuracy: Low
        $x_2_2 = "c:\\windows\\help\\winhelp.exe" ascii //weight: 2
        $x_1_3 = "/j.jsp?p" ascii //weight: 1
        $x_1_4 = {26 70 33 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 70 34 3d}  //weight: 1, accuracy: Low
        $x_1_5 = "/add.jsp?uid=" ascii //weight: 1
        $x_1_6 = {26 76 65 72 3d ?? ?? ?? ?? ?? 26 6d 61 63 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

