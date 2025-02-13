rule Worm_Win32_Nelboomro_B_2147644393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Nelboomro.B"
        threat_id = "2147644393"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Nelboomro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 37 2f 47 49 85 c9 75 f7}  //weight: 1, accuracy: High
        $x_1_2 = {e8 0c 00 00 00 68 6f 6c 61 7c 4e 6f 6d 62 72 65 00 ff 35}  //weight: 1, accuracy: High
        $x_1_3 = {83 f8 02 0f 85 ?? ?? 00 00 66 81 3b 41 3a 75 05 e9}  //weight: 1, accuracy: Low
        $x_1_4 = {7e 21 81 38 45 78 69 74 75 08 6a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

