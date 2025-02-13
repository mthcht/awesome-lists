rule Trojan_Win32_Squida_A_2147681305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Squida.A"
        threat_id = "2147681305"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Squida"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 73 6c 6f 77 70 6f 73 74 00 73 6c 6f 77 6c 6f 72 69 73 00}  //weight: 1, accuracy: High
        $x_1_2 = "SCHTASKS /CREATE /SC ONLOGON /TN A" ascii //weight: 1
        $x_1_3 = "%s %s :%s IRC War: Stopped Kill Multiple Users" ascii //weight: 1
        $x_3_4 = {41 ba 05 15 00 00 89 d6 c1 e6 05 8d 04 06 01 c2 0f be 01 41 85 c0 75 ee}  //weight: 3, accuracy: High
        $x_2_5 = {73 6b 79 70 65 00 6c 6f 63 6b 00 62 6f 74 6b 69 6c 6c 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Squida_C_2147681865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Squida.C"
        threat_id = "2147681865"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Squida"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Flooding with Slowloris. IP:" wide //weight: 1
        $x_1_2 = "\\LongLat.txt" wide //weight: 1
        $x_1_3 = "bs_fusion_bot" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

