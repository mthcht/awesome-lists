rule TrojanDownloader_Win32_Mondow_A_2147729869_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Mondow.A!bit"
        threat_id = "2147729869"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Mondow"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 74 74 70 3a 2f 2f 37 2e 34 35 36 37 37 37 38 39 2e 63 6f 6d [0-48] 2e 65 78 65}  //weight: 2, accuracy: Low
        $x_1_2 = {00 6b 73 61 66 65 74 72 61 79 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 73 63 76 68 6f 73 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 43 3a 5c 6d 6f 6f 6e 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = "reg add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

