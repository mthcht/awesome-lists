rule TrojanDropper_Win64_VeepLoad_A_2147964131_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/VeepLoad.A!dha"
        threat_id = "2147964131"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "VeepLoad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ba 0b fd 8e 55 48 8b cb 48 8b f8 e8}  //weight: 1, accuracy: High
        $x_1_2 = {ba 31 78 21 62 48 89 06 48 8b cb e8}  //weight: 1, accuracy: High
        $x_1_3 = {ba 2d 57 16 5f 48 89 46 08 48 8b cb e8}  //weight: 1, accuracy: High
        $x_1_4 = {ba 01 6d 29 83 48 89 46 10 48 8b cf e8}  //weight: 1, accuracy: High
        $x_1_5 = {ba d8 30 8c 68 48 89 46 18 48 8b cf e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

