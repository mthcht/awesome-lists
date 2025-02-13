rule Worm_Win32_Racvacs_A_2147640889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Racvacs.A"
        threat_id = "2147640889"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Racvacs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 0c 00 00 00 61 75 74 6f 72 75 6e 2e 69 6e 66 00 53}  //weight: 1, accuracy: High
        $x_1_2 = {0f 31 89 c3 0f 31 89 c1 0f 31 89 c2 0f 31 89 c7 0f 31 53 51 52 57 50}  //weight: 1, accuracy: High
        $x_1_3 = {c6 07 5c 47 0f 31 56 50 e8 06 00 00 00 25 78 2e 25 73 00 57 ff}  //weight: 1, accuracy: High
        $x_1_4 = {81 3e 48 54 54 50 75 13 46 4b 66 39 3e 75 f9 66 39 7e 02 75 f3}  //weight: 1, accuracy: High
        $x_1_5 = {f6 12 42 e2 fb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

