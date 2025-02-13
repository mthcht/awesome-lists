rule TrojanDropper_Win32_Alobtoe_A_2147626877_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Alobtoe.A"
        threat_id = "2147626877"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Alobtoe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 64 ff 30 64 89 20 00 00 68 ?? ?? 40 00 33 c0 64 ff 30 64 89 20 00 00 81 c4 b0 07 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 40 00 00 00 83 c4 28 68 ?? ?? 40 00 e8 c3 03 00 00 a3 ?? ?? 40 00 90 90 90}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

