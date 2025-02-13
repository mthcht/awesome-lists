rule Backdoor_Win32_Dawkhu_A_2147610172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Dawkhu.A"
        threat_id = "2147610172"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Dawkhu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f c6 44 24 ?? 73 c6 44 24 ?? 68 c6 44 24 ?? 75 c6 44 24 ?? 74 c6 44 24 ?? 0d c6 44 24 ?? 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {66 89 b4 24 ?? 01 00 00 33 c0 81 e6 ff ff 00 00 c7 84 ?? ?? 01 00 00 ?? ?? ?? ?? 89 94 ?? ?? 01 00 00 66 c7 84 24 ?? 01 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2d c6 44 24 ?? 30 c6 44 24 ?? 3d c6 44 24 ?? 4f c6 44 24 ?? 70 c6 44 24 ?? 65 c6 44 24 ?? 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

