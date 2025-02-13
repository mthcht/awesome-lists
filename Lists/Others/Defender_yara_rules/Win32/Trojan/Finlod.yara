rule Trojan_Win32_Finlod_A_2147757906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Finlod.A"
        threat_id = "2147757906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Finlod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c1 6d 68 ed}  //weight: 2, accuracy: High
        $x_2_2 = {21 3b df 50}  //weight: 2, accuracy: High
        $x_2_3 = {91 fd 47 59}  //weight: 2, accuracy: High
        $x_2_4 = {7f 28 a0 69}  //weight: 2, accuracy: High
        $x_2_5 = {2f 44 d4 9b}  //weight: 2, accuracy: High
        $x_2_6 = {fd 42 72 b6}  //weight: 2, accuracy: High
        $x_1_7 = {83 c0 30 ff d0 68 00 80 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {48 83 c0 30 ff d0 41 b9 00 80 00 00}  //weight: 1, accuracy: High
        $x_1_9 = "\\REGISTRY\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

