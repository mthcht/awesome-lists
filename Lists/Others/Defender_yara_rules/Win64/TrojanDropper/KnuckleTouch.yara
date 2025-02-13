rule TrojanDropper_Win64_KnuckleTouch_A_2147900043_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/KnuckleTouch.A!dha"
        threat_id = "2147900043"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "KnuckleTouch"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {69 f6 fd 43 03 00 33 d2 81 c6 c3 9e 26 00 8b c6 c1 e8 10 25 ff 7f 00 00 f6 c1 01 74}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

