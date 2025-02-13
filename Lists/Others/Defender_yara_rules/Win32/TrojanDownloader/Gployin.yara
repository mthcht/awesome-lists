rule TrojanDownloader_Win32_Gployin_A_2147721631_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Gployin.A!bit"
        threat_id = "2147721631"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Gployin"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 69 00 6d 00 64 00 2e 00 67 00 64 00 79 00 69 00 70 00 69 00 6e 00 67 00 2e 00 63 00 6f 00 6d 00 [0-48] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = "c:\\windows\\temp\\winlogon.exe" wide //weight: 1
        $x_1_3 = "software\\microsoft\\windows\\currentVersion\\run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

