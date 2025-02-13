rule Virus_Win32_Inbind_A_2147640463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Inbind.A"
        threat_id = "2147640463"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Inbind"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 7c 24 08 55 81 18 55 0f 94 c3}  //weight: 1, accuracy: High
        $x_1_2 = {2b 7c 24 0c 83 ef 08 8b c7 99 81 e2 ff 03 00 00 03 c2 c1 f8 0a 85 c0 7e}  //weight: 1, accuracy: High
        $x_1_3 = {00 69 6e 66 65 63 74 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

