rule TrojanDropper_Win32_Lavtds_A_2147627465_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Lavtds.A"
        threat_id = "2147627465"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Lavtds"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c1 04 35 98 98 74 92 81 f9 c8 2c 00 00 89 84 2a ?? ?? ?? ?? 89 ca 75 e1}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 27 72 66 ?? ?? ?? 41 30 29 18 e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? 89 ?? ?? ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

