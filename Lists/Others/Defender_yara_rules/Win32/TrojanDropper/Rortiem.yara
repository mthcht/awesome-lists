rule TrojanDropper_Win32_Rortiem_A_2147658137_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Rortiem.A"
        threat_id = "2147658137"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Rortiem"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 17 8d 45 ?? 50 ff 55 ?? 3d 61 00 00 c0 74 09 c7 45 ?? 01 00 00 00 eb ?? 68 3f 00 0f 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 40 02 00 00 50 6a 03 6a 0b ff 75 ?? ff 15 ?? ?? ?? ?? 85 c0 75 0d ff 15 ?? ?? ?? ?? 3d ea 00 00 00 75 ?? 39 75 ?? 89 75 ?? 7e ?? 8b 4d 08 8d 04 9b c1 e0 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

