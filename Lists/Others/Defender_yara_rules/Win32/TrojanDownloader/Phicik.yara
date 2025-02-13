rule TrojanDownloader_Win32_Phicik_A_2147646032_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Phicik.A"
        threat_id = "2147646032"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Phicik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 69 6e 64 6f 77 73 20 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 [0-4] 48 44 69 64 [0-4] 25 75 2e 25 75 2e 25 75 2e 25 75 7c [0-16] 25 73 7c 25 73 7c 25 73 7c 25 73 7c 25 73 7c 25 73 [0-4] 50 4f 53 54 [0-4] 64 3d 25 73 26 69 3d 25 73}  //weight: 1, accuracy: Low
        $x_1_2 = "BASEWND" ascii //weight: 1
        $x_1_3 = "DeleteUrlCacheEntry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

