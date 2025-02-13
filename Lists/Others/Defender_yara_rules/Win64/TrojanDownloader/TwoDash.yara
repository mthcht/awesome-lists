rule TrojanDownloader_Win64_TwoDash_A_2147926517_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/TwoDash.A!dha"
        threat_id = "2147926517"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "TwoDash"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {69 c9 fd 43 03 00 81 c1 c3 9e 26 00 8b c1 c1 e8 18 30 82 ?? ?? ?? ?? 42 81 fa ?? ?? ?? ?? 72}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

