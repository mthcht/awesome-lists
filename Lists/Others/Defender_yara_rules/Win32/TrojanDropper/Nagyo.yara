rule TrojanDropper_Win32_Nagyo_A_2147622281_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Nagyo.A"
        threat_id = "2147622281"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Nagyo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "256dc5e0e-7c46-11d3-b5bf-0000f8695621" ascii //weight: 1
        $x_1_2 = {68 00 04 00 00 81 c9 00 b0 08 00 52 8b ?? ?? ?? 8d ?? ?? ?? 6a 02 50 c1 e1 02 51 52 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 66 6a 00 ff 15 ?? ?? 40 00 8b f0 85 f6 75 07 5f 5e 5b 83 c4 44 c3 56 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

