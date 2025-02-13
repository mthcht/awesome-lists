rule TrojanDownloader_Win32_Subroate_A_2147708986_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Subroate.A!bit"
        threat_id = "2147708986"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Subroate"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 01 56 8b f2 84 c0 74 0e 2b ca 34 7f 88 02 42 8a 04 11 84 c0 75 f4 8b c6 c6 02 00 5e c3}  //weight: 1, accuracy: High
        $x_1_2 = {00 53 74 75 62 2e 64 6c 6c 00 5f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

