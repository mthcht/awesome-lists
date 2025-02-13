rule Trojan_Win32_Phaetp_E_2147816249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phaetp.E!dha"
        threat_id = "2147816249"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phaetp"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\Insdll.pdb" ascii //weight: 2
        $x_2_2 = "\\exp\\NewPop\\" ascii //weight: 2
        $x_2_3 = "httpshelper.dll" ascii //weight: 2
        $x_1_4 = {48 74 74 70 73 49 6e 69 74 00}  //weight: 1, accuracy: High
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Phaetp_F_2147816250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phaetp.F!dha"
        threat_id = "2147816250"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phaetp"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {68 74 74 70 73 68 65 6c 70 65 72 2e 64 6c 6c 00 48 74 74 70 73 49 6e 69 74}  //weight: 3, accuracy: High
        $x_2_2 = "xoxo.myddns.com" ascii //weight: 2
        $x_1_3 = {25 30 31 36 49 36 34 78 25 30 38 78 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

