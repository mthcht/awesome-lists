rule TrojanDownloader_Win32_Bedep_A_2147709041_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bedep.A"
        threat_id = "2147709041"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bedep"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 c2 03 66 83 f8 41 72 0e 66 83 f8 5a 77 08 0f b7 c0 83 c8 20 eb 03}  //weight: 1, accuracy: High
        $x_1_2 = {8b 41 3c 6a 01 8b 44 08 28 51 03 c1 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

