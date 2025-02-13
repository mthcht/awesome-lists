rule TrojanDropper_Win32_DinoTrain_2147811384_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/DinoTrain.gen!dha"
        threat_id = "2147811384"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "DinoTrain"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 83 c4 ?? 03 da 33 c9 2b c2 74 ?? 8a 44 19 ?? 84 c0 74 ?? 30 04 19 8b 95 ?? ?? ?? ?? 8b c7 41 2b c2 3b c8 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

