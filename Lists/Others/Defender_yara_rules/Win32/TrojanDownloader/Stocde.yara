rule TrojanDownloader_Win32_Stocde_A_2147718611_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Stocde.A!bit"
        threat_id = "2147718611"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Stocde"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmdshell_deinit" ascii //weight: 1
        $x_1_2 = "stop sharedaccess" ascii //weight: 1
        $x_1_3 = "\\%c%c%c%c%c.exe" ascii //weight: 1
        $x_1_4 = {2e 65 78 65 00 00 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

