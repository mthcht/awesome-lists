rule TrojanDownloader_Win32_Namsoth_A_2147629008_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Namsoth.A"
        threat_id = "2147629008"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Namsoth"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b1 6e b2 74 33 db}  //weight: 2, accuracy: High
        $x_2_2 = {88 5c 24 1f c6 44 24 20 49 88 4c 24 21 88 54 24 22 c6 44 24 24 72 88 4c 24 25 88 54 24 27 c6 44 24 28 52 c6 44 24 2a 61}  //weight: 2, accuracy: High
        $x_1_3 = "&userid=%04d&other=%c%s" ascii //weight: 1
        $x_1_4 = "  Wait for %02d minute(s)..." ascii //weight: 1
        $x_1_5 = {43 6f 6e 6e 65 63 74 69 6f 6e 20 43 6f 6d 69 6e 67 21 0a 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

