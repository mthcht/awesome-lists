rule TrojanDropper_Win32_Popureb_A_2147646126_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Popureb.A"
        threat_id = "2147646126"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Popureb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d2 c8 88 04 46 59 e2}  //weight: 1, accuracy: High
        $x_1_2 = {81 c1 00 28 00 00 83 d2 00 81 e9 00 02 00 00 83 da 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

