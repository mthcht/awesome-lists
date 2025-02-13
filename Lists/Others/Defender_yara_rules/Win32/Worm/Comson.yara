rule Worm_Win32_Comson_A_2147643228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Comson.A"
        threat_id = "2147643228"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Comson"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 0a 50 33 c0 83 c2 f8 85 d2 76}  //weight: 1, accuracy: High
        $x_1_2 = {b8 67 66 66 66 80 c2 30 88 94 ?? ?? ff ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {75 06 39 7c 08 04 74 ?? 40 3b ?? 72 ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

