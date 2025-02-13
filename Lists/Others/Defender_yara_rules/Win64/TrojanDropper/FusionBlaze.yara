rule TrojanDropper_Win64_FusionBlaze_A_2147725398_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/FusionBlaze.A!dha"
        threat_id = "2147725398"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "FusionBlaze"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6f 72 7a 5f 52 65 73 52 65 6c 65 61 73 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {5b 2b 5d 20 69 6e 73 2e 65 78 65 20 2d 73 76 63 20 73 76 63 4e 61 6d 65 20 28 69 6e 73 74 61 6c 6c 20 77 69 74 68 20 73 70 65 63 69 66 69 65 64 20 73 76 63 29 00}  //weight: 1, accuracy: High
        $x_1_3 = {6f 72 7a 5f 53 43 47 65 74 4e 65 74 73 76 63 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

