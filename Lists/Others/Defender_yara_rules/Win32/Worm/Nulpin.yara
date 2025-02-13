rule Worm_Win32_Nulpin_A_2147616032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Nulpin.A"
        threat_id = "2147616032"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Nulpin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb ea 3b c1 75 12 83 f9 40 73 0d}  //weight: 1, accuracy: High
        $x_3_2 = {74 1f 8a 0c 32 8a c2 2c ?? 8b fe d0 e0 02 c8 33 c0 88 0c 32 83 c9 ff 42 f2 ae f7 d1 49 3b d1 72 e1}  //weight: 3, accuracy: Low
        $x_1_3 = {6d 73 63 6f 6e 67 6d 75 74 65 78 00}  //weight: 1, accuracy: High
        $x_1_4 = {73 75 63 68 6f 74 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {47 45 54 20 2f 4e 55 4c 4c 2e 70 72 69 6e 74 65 72 0a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

