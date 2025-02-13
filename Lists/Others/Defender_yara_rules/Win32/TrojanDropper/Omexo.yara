rule TrojanDropper_Win32_Omexo_A_2147626895_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Omexo.A"
        threat_id = "2147626895"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Omexo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 39 50 45 00 00 75 14 8b 95 ?? ?? ?? ?? 8b 42 50 50 8b 4d fc 51 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c9 3d 01 00 00 c0 0f 94 c1 89 8d ?? ?? ?? ?? 68 00 80 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

