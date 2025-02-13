rule TrojanDropper_WinNT_Mediyes_C_2147655212_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:WinNT/Mediyes.C"
        threat_id = "2147655212"
        type = "TrojanDropper"
        platform = "WinNT: WinNT"
        family = "Mediyes"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 fe 38 04 00 00 76 0a bf 03 00 00 00 8b c7 5f 5e c3 83 f8 0a 75 40 81 fe ce 07 00 00 75 0a}  //weight: 1, accuracy: High
        $x_1_2 = {83 f8 68 74 [0-2] e8 [0-2] 00 00 83 f8 ?? 74 ?? e8 [0-2] 00 00 83 f8 6b 74 ?? 8b 85 ?? ?? ff ff 83 08 48}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

