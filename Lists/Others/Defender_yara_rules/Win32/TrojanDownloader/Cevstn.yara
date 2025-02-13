rule TrojanDownloader_Win32_Cevstn_B_2147613014_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cevstn.B"
        threat_id = "2147613014"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cevstn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 21 53 8b 44 24 08 8d 0c 02 8a 04 02 2a c2 8a d8 c0 eb 04 c0 e0 04 02 d8 42 3b 54 24 0c 88 19 7c e1}  //weight: 1, accuracy: High
        $x_1_2 = {74 31 88 18 8d 85 ?? ?? ff ff 6a 5c 50 ff 15 ?? ?? 40 00 59 3b c3 59 74 1a 80 78 ff 3a 75 05 88 58 01 eb 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

