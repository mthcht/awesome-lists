rule Trojan_Win32_Msposer_F_2147663936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Msposer.F"
        threat_id = "2147663936"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Msposer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "D:\\Code\\xsys\\Explorer.vbp" wide //weight: 10
        $x_10_2 = {3c 00 41 00 74 00 74 00 61 00 63 00 6b 00 3e [0-32] 3c 00 2f 00 41 00 74 00 74 00 61 00 63 00 6b 00 3e}  //weight: 10, accuracy: Low
        $x_1_3 = {3c 00 4d 00 61 00 69 00 6c 00 3e [0-32] 3c 00 2f 00 4d 00 61 00 69 00 6c 00 3e}  //weight: 1, accuracy: Low
        $x_1_4 = {3c 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 3e [0-32] 3c 00 2f 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 3e}  //weight: 1, accuracy: Low
        $x_1_5 = {3c 00 55 00 70 00 64 00 61 00 74 00 65 00 3e [0-32] 3c 00 2f 00 55 00 70 00 64 00 61 00 74 00 65 00 3e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Msposer_L_2147673735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Msposer.L"
        threat_id = "2147673735"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Msposer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "||SplitMe||" wide //weight: 1
        $x_1_2 = "\\Temporary Projects\\Chrome\\obj\\x86\\Debug\\Chrome.pdb" ascii //weight: 1
        $x_1_3 = {43 6f 70 79 72 69 67 68 74 20 c2 a9 20 4d (69 63 72|65 67) 6f 66 74 20 32 30 31 32 [0-15] 43 68 72 6f 6d 65 [0-15] 4d (69 63 72|65 67) 6f 66 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Msposer_G_2147678458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Msposer.G"
        threat_id = "2147678458"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Msposer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//s14.cnzz.com/stat.php?id=4730427&web_id=4730427" ascii //weight: 1
        $x_1_2 = {2f 73 74 61 74 2f 67 61 6d 65 2e 70 68 70 3f 74 79 70 65 3d 00 00 00 00 77 77 77 2e 68 75 69 66 65 69 64 65 7a 68 75 2e 63 6f 6d}  //weight: 1, accuracy: High
        $x_1_3 = "\\ext\\settings\\{11f09afe-75ad-4e52-ab43-e09e9351ce17}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

