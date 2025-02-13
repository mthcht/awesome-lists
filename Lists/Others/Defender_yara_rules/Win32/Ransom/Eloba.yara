rule Ransom_Win32_Eloba_A_2147690964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Eloba.A"
        threat_id = "2147690964"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Eloba"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 65 6c 70 40 61 6e 74 69 76 69 72 75 73 65 62 6f 6c 61 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_2 = "denge.batcave.net/gaza/" ascii //weight: 1
        $x_1_3 = "dayriyzyith.comeze.com/" ascii //weight: 1
        $x_1_4 = {65 62 6f 6c 61 2e 62 6d 70 00}  //weight: 1, accuracy: High
        $x_1_5 = {32 33 63 65 30 31 32 37 2d 35 65 33 35 2d 34 62 39 61 2d 61 61 32 64 2d 35 64 61 62 36 65 66 63 38 39 30 35 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

