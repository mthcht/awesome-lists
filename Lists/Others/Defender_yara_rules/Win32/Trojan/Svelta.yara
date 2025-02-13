rule Trojan_Win32_Svelta_A_2147627562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Svelta.A"
        threat_id = "2147627562"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Svelta"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b2 be b1 ad b0 de 88 54 ?? 0e 88 4c 24 0f 88 44 24 10 88 4c 24 16}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 46 04 6a 00 89 4e 09 8b 0e 51 55 53 57 89 56 10 89 46 15}  //weight: 1, accuracy: High
        $x_1_3 = {66 69 72 65 66 6f 78 2e 65 78 65 00 69 65 78 70 6c 6f 72 65 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

