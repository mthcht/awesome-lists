rule TrojanDownloader_Win64_Tickler_B_2147919672_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Tickler.B!dha"
        threat_id = "2147919672"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Tickler"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 09 04 02 81 f7 e9 03 d1 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 2b c8 43 88 0c 01 49 ff c0 4d 8d 52 04 49 81 f8 83 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

