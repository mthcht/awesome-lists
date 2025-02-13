rule TrojanDropper_Win64_Foosace_A_2147710121_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/Foosace.A!dha"
        threat_id = "2147710121"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "Foosace"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 1e 41 8a 34 19 8a c2 ff c2 41 f6 e9 41 02 c2 40 32 f0 41 88 34 19 44 8a 14 0a 45 84 d2 75 e6}  //weight: 1, accuracy: High
        $x_1_2 = {66 69 6c 65 78 6f 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

