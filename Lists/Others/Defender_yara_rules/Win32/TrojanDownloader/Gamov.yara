rule TrojanDownloader_Win32_Gamov_A_2147636893_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Gamov.A"
        threat_id = "2147636893"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamov"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 55 49 44 54 61 6f 00}  //weight: 1, accuracy: High
        $x_1_2 = {74 61 6f 62 61 6f 2e 69 63 6f ?? ?? ?? ?? ?? ?? 6d 6f 76 69 65 2e 69 63 6f ?? ?? ?? 6d 6d 2e 69 63 6f ?? ?? ?? ?? ?? ?? 67 61 6d 65 2e 69 63 6f}  //weight: 1, accuracy: Low
        $x_1_3 = "Love360=4*90+R+ing*360" ascii //weight: 1
        $x_1_4 = "61rr.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

