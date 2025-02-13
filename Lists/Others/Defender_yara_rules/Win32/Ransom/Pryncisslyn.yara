rule Ransom_Win32_Pryncisslyn_A_2147720979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Pryncisslyn.A"
        threat_id = "2147720979"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Pryncisslyn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/decrypt.exe" wide //weight: 1
        $x_1_2 = "/btc.php?id=" wide //weight: 1
        $x_1_3 = "/adr.php?id=" wide //weight: 1
        $x_1_4 = "/data.php?id=" wide //weight: 1
        $x_2_5 = {40 00 65 00 63 00 68 00 6f 00 20 00 6f 00 66 00 66 00 [0-6] 74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 69 00 6d 00 20 00 64 00 65 00 63 00 72 00 79 00 70 00 74 00 2e 00 65 00 78 00 65 00 [0-6] 64 00 65 00 6c 00}  //weight: 2, accuracy: Low
        $x_2_6 = {44 00 65 00 63 00 72 00 79 00 70 00 74 00 46 00 69 00 6c 00 65 00 73 00 [0-6] 69 00 64 00 2e 00 74 00 78 00 74 00 [0-6] 6c 00 6e 00 6b 00 2e 00 74 00 78 00 74 00}  //weight: 2, accuracy: Low
        $x_2_7 = {64 00 65 00 6c 00 2e 00 62 00 61 00 74 00 [0-6] 2e 00 67 00 72 00 74 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

