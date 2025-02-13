rule Trojan_Win32_Servjum_A_2147628113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Servjum.A"
        threat_id = "2147628113"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Servjum"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4f 50 65 65 6b 2e 65 78 65 00 00 00 49 6d 6d 75 6e 69 74 79 44 65 62 75 67 67 65 72 2e 65 78 65 00 00 00 00 77 69 6e 64 62 67 2e 65 78 65 00 00 72 65 67 6d 6f 6e 2e 65 78 65 00 00 65 74 68 65 72 65 61 6c 2e 65 78 65 00 00 00 00 69 72 69 73 2e 65 78 65 00 00 00 00 69 64 61 67 2e 65 78 65 00 00 00 00 6f 6c 6c 79 64 62 67 2e 65 78 65 00 66 69 6c 65 6d 6f 6e 2e 65 78 65 00 77 69 72 65 73 68 61 72 6b 2e 65 78 65 00 00 00 44 00 65 00 62 00 75 00 67 00 4f 00 62 00 6a 00 65 00 63 00 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

