rule TrojanDropper_Win64_RollSling_A_2147892514_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/RollSling.A!dha"
        threat_id = "2147892514"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "RollSling"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "200"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "-DF09-AA86-YI78-" ascii //weight: 100
        $x_100_2 = "-09C7-886E-II7F-" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

