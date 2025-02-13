rule Trojan_Win32_Mobsularch_A_2147680309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mobsularch.A"
        threat_id = "2147680309"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mobsularch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d0 9a d0 be d0 b4 20 d0 b0 d0 ba d1 82 d0 b8 d0 b2 d0 b0 d1 86 d0 b8 d0 b8}  //weight: 1, accuracy: High
        $x_1_2 = {d0 a1 d1 82 d0 be d0 b8 d0 bc d0 be d1 81 d1 82 d1 8c 20 53 4d 53 2d d1 81 d0 be d0 be d0 b1 d1 89 d0 b5 d0 bd d0 b8 d1 8f 20}  //weight: 1, accuracy: High
        $x_1_3 = {d0 b2 d0 b2 d0 b5 d1 81 d1 82 d0 b8 20 d0 bd d0 be d0 bc d0 b5 d1 80 20 d1 81 d0 b2 d0 be d0 b5 d0 b3 d0 be 20 d0 bc d0 be d0 b1 d0 b8 d0 bb d1 8c d0 bd d0 be d0 b3 d0 be 20 d1 82 d0 b5 d0 bb d0 b5 d1 84 d0 be d0 bd d0 b0}  //weight: 1, accuracy: High
        $x_1_4 = {d0 bd d0 be d0 bc d0 b5 d1 80 3a 20 d0 bd d0 b0 20 d0 bd d0 b5 d0 b3 d0 be 20 d0 bf d1 80 d0 b8 d0 b4 d0 b5 d1 82 20 d0 bf d1 80 d0 be d0 b2 d0 b5 d1 80 d0 be d1 87 d0 bd d1 8b d0 b9 20 d0 ba d0 be d0 b4}  //weight: 1, accuracy: High
        $x_5_5 = "/customers/app_launch.php?id_project=" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

