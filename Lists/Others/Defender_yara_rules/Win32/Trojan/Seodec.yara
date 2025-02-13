rule Trojan_Win32_Seodec_A_2147691147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Seodec.A"
        threat_id = "2147691147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Seodec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "QQ1003175" ascii //weight: 1
        $x_1_2 = {2e 65 78 65 00 74 69 6d 65}  //weight: 1, accuracy: High
        $x_1_3 = "/new/dxc.txt" ascii //weight: 1
        $x_1_4 = "/new/ip.asp" ascii //weight: 1
        $x_1_5 = {57 69 6e 48 74 74 70 2e 57 69 6e 48 74 74 70 52 65 71 75 65 73 74 2e 35 2e 31 00 47 45 54}  //weight: 1, accuracy: High
        $x_1_6 = {53 65 74 50 72 6f 78 79 00 53 65 74 50 72 6f 78 79 43 72 65 64 65 6e 74 69 61 6c 73 00 4f 70 65 6e 00 4f 70 74 69 6f 6e}  //weight: 1, accuracy: High
        $x_1_7 = {26 73 69 64 3d 00 26 75 69 64 3d 00 26 69 64 3d 00 26 73 64 3d 76 65 72 [0-2] 2e [0-5] 2d 00 26 6d 61 63 3d 00 3f 69 70 3d [0-64] 3f 75 69 64 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

