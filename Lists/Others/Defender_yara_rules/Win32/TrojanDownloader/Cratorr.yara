rule TrojanDownloader_Win32_Cratorr_A_2147608017_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cratorr.gen!A"
        threat_id = "2147608017"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cratorr"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {83 65 fc 00 8b 75 08 6a 04 bf ?? ?? ?? ?? 59 33 c0 f3 a6 74 05 1b c0 83 d8 ff 85 c0 75 07 b8 ?? ?? ?? ?? eb 43 8b 75 08 6a 09}  //weight: 3, accuracy: Low
        $x_1_2 = "FILE0=\"crack.exe" ascii //weight: 1
        $x_1_3 = {2f 63 72 61 63 6b 2f 28 5c 64 2b 29 2f 22 3e 28 5b 5e 3c 5d 2b 29 3c 2f 61 3e 00}  //weight: 1, accuracy: High
        $x_1_4 = "10:created by" ascii //weight: 1
        $x_1_5 = {37 3a 63 6f 6d 6d 65 6e 74 25 64 3a 25 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

