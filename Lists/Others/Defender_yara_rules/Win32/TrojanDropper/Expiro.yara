rule TrojanDropper_Win32_Expiro_B_2147645058_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Expiro.B"
        threat_id = "2147645058"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Expiro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 d0 88 04 3e 80 05 ?? ?? ?? ?? 01 0f b6 05 ?? ?? ?? ?? 3d ff 00 00 00 75 07 c6 05 ?? ?? ?? ?? 00 83 65 ?? 00 eb 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

