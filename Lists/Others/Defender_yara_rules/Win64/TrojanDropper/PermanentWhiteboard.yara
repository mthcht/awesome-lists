rule TrojanDropper_Win64_PermanentWhiteboard_A_2147939637_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/PermanentWhiteboard.A!dha"
        threat_id = "2147939637"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "PermanentWhiteboard"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "DroneEXEHijackingLoader.dll" ascii //weight: 1
        $x_1_2 = {41 bf 00 28 00 00 41 be ff 03 00 00 41 bc 00 24 00 00 0f b7 d1 41 8d 04 0f 66 41 3b c6 77 ?? 8b fa c1 e7 0a 81 ef 00 00 5f 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

