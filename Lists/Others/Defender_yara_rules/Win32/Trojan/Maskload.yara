rule Trojan_Win32_Maskload_A_2147622487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Maskload.A"
        threat_id = "2147622487"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Maskload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 01 6a 00 c7 05 ?? ?? ?? ?? 4c 6f 61 64 c7 05 ?? ?? ?? ?? 65 72 00 00 ff 15 ?? ?? ?? ?? 8b e8 85 ed}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 10 83 c0 04 81 f2 4b 53 41 4d 89 11 83 c1 04 3d ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 14 08 80 f2 ?? 88 14 08 40 83 f8 0c 7c f1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

