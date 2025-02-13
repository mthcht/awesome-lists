rule Worm_Win32_Bewmecky_A_2147626859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bewmecky.A"
        threat_id = "2147626859"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bewmecky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 08 88 0a 83 c0 01 83 c2 01 84 c9 75 f2 e9 ?? ?? ?? ?? 83 ff 02 75 28}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 14 19 83 c3 01 80 fa 40 74 08 81 fb f4 01 00 00 7c ed 33 c0 33 f6 85 db bf 01 00 00 00 0f 8e ?? ?? 00 00 80 3c 31 23}  //weight: 1, accuracy: Low
        $x_1_3 = "[autorun]" ascii //weight: 1
        $x_1_4 = "\\recycler" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

