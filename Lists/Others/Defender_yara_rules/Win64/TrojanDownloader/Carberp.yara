rule TrojanDownloader_Win64_Carberp_A_2147725009_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Carberp.A!bit"
        threat_id = "2147725009"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Carberp"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 33 db 4c 8b c9 45 8b c3 45 8a d3 66 44 39 19 74 1f 41 0f b6 11 4d 8d 49 02 44 32 d2 44 33 c2 41 80 e2 1f 41 0f b6 ca 41 d3 c0 66 45 39 19 75 e1}  //weight: 1, accuracy: High
        $x_1_2 = {76 6e 63 64 6c 6c 36 34 2e 64 6c 6c 00 56 6e 63 53 74 61 72 74 53 65 72 76 65 72 00 56 6e 63 53 74 6f 70 53 65 72 76 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

