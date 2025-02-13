rule Backdoor_Win32_Wykcores_A_2147643781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Wykcores.A"
        threat_id = "2147643781"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Wykcores"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {43 83 c6 48 83 c7 44 83 fb 04 75 b6 33 c0 89 45 0c 33 c0 89 45 14 33 c0 89 45 1c b0 01 81 c4 34 02 00 00 5d 5f 5e 5b c3}  //weight: 2, accuracy: High
        $x_2_2 = {8b cb 8a 55 b8 d2 e2 30 10 43 40 83 fb 10 75 f0}  //weight: 2, accuracy: High
        $x_1_3 = "SOFTWARE\\Classes\\Sxl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

