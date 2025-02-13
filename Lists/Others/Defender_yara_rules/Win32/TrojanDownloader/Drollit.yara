rule TrojanDownloader_Win32_Drollit_A_2147598159_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Drollit.A"
        threat_id = "2147598159"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Drollit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d0 8b f0 3b f3 74 4d 8d 45 e0 50 56 68 a5 c0 61 e8 e8 ?? ?? ff ff ff d0 85 c0 74 0a 83 7d e4 04 75 04 b3 01 eb 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

