rule Trojan_Win32_Cerevx_A_2147661325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cerevx.A"
        threat_id = "2147661325"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerevx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 8b 4d 08 8a 11 8d 41 01 84 d2 74 0e c6 01 00 30 10 8b c8 74 05 41 30 11 75 fb 5d c3}  //weight: 1, accuracy: High
        $x_1_2 = {5c 6a 61 76 61 25 73 2e 65 78 65 [0-16] 5c 6a 61 76 61 77 25 73 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

