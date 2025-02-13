rule TrojanDropper_Win64_ClearMarbles_A_2147837650_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/ClearMarbles.A!dha"
        threat_id = "2147837650"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "ClearMarbles"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {b8 4f ec c4 4e f7 e9 c1 fa 02 8b c2 c1 e8 1f 03 d0 6b d2 0d 8b c1 2b c2 48 98 0f b6 14 18 41 30 10 ff c1}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

