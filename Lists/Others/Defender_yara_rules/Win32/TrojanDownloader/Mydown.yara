rule TrojanDownloader_Win32_Mydown_B_2147599183_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Mydown.gen!B"
        threat_id = "2147599183"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Mydown"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "mwinsys.ini" ascii //weight: 1
        $x_1_2 = "dll_hitpop" ascii //weight: 1
        $x_1_3 = "dll_start" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\run" ascii //weight: 1
        $x_1_5 = "mydown" ascii //weight: 1
        $x_1_6 = "checkcj" ascii //weight: 1
        $x_3_7 = {79 6d 61 6e 74 65 63 20 41 6e 74 69 56 69 72 75 73 00 00 00 ff ff ff ff 01 00 00 00 53 00 00 00 ff ff ff ff 04 00 00 00 6f 64 33 32}  //weight: 3, accuracy: High
        $x_10_8 = {8b 4d fc 8a 4c 11 ff 8b 75 ec 88 0c 1e 43 42 48 75 ee 8b 45 f8 e8 ?? ?? ?? ?? 85 c0 7e 17 ba 01 00 00 00 8b 4d f8 8a 4c 11 ff 8b 75 ec 88 0c 1e 43 42 48 75 ee}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

