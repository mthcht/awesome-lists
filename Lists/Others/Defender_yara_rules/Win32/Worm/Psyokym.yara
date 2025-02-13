rule Worm_Win32_Psyokym_A_2147654086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Psyokym.A"
        threat_id = "2147654086"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Psyokym"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 79 20 59 50 53 20 20 2d 20 4b 65 79 4c 6f 67 67 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = "H1i1d1e1F1i1l1e1E1x1t1" wide //weight: 1
        $x_1_3 = "[AutoRun]" wide //weight: 1
        $x_1_4 = "ysp\\ysp.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Psyokym_B_2147654954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Psyokym.B"
        threat_id = "2147654954"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Psyokym"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 79 20 59 50 53 20 20 2d 20 4b 65 79 4c 6f 67 67 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = "/extract.php?x=" wide //weight: 1
        $x_1_3 = "autorun.inf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Psyokym_C_2147710604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Psyokym.C"
        threat_id = "2147710604"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Psyokym"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 79 20 59 50 53 20 20 2d 20 4b 65 79 4c 6f 67 67 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = "H1i1d1e1F1i1l1e1E1x1t1" wide //weight: 1
        $x_1_3 = "http://www.hoarafushionline.net/habeys.exe" wide //weight: 1
        $x_1_4 = "http://www.hoarafushionline.net/extractf.php?x=" wide //weight: 1
        $x_1_5 = "ysp\\ysp.vbp" wide //weight: 1
        $x_1_6 = "1A1u1t1o1r1u1n1.1i1n1f1" wide //weight: 1
        $x_1_7 = "[1A1u1t1o1R1u1n]" wide //weight: 1
        $x_1_8 = "S1O1F1T1W1A1R1E1\\1Microsoft1\\1W1i1n1d1o1w1s1\\1C1u1r1r1e1n1t1V1e1r1s1i1o1n1\\1R1u1n1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

