rule Trojan_Win32_Safel_A_2147611453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Safel.A"
        threat_id = "2147611453"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Safel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {68 8d bd c1 3f}  //weight: 2, accuracy: High
        $x_2_2 = {9f a9 a2 af a9 a1 f1 ea af a4 e3 00}  //weight: 2, accuracy: High
        $x_1_3 = {22 25 73 22 00}  //weight: 1, accuracy: High
        $x_1_4 = {73 66 6c 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

