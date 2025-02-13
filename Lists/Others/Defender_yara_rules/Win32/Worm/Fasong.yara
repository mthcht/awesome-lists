rule Worm_Win32_Fasong_I_2147670891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Fasong.I"
        threat_id = "2147670891"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Fasong"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 f8 03 75 0a 8b d6 8b 45 fc e8 ?? ?? ?? ?? 43 83 fb 57 75 c3}  //weight: 10, accuracy: Low
        $x_1_2 = {61 75 74 6f 72 75 6e 2e 69 6e 66 ?? ?? ?? ?? ?? ?? ?? ?? ?? 5b 61 75 74 6f 72 75 6e 5d}  //weight: 1, accuracy: Low
        $x_1_3 = {73 76 72 61 70 69 2e 64 6c 6c 00 00 4e 65 74 53 68 61 72 65 41 64 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 6b 61 76 73 76 63 75 69 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 70 61 73 73 77 6f 72 64 67 75 61 72 64 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 66 61 73 6f 6e 67 5f 79 6f 75 78 69 61 6e 67 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 73 6d 74 70 5f 66 75 77 75 71 69 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 71 71 70 61 73 73 37 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

