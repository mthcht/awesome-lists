rule Trojan_Win32_Strigy_A_2147644491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strigy.A"
        threat_id = "2147644491"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strigy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "odbc_yek.nls" ascii //weight: 3
        $x_2_2 = "Enter MyWork..." ascii //weight: 2
        $x_1_3 = " stop wuauserv" ascii //weight: 1
        $x_2_4 = {3a 20 4d 79 41 70 70 2f 30 2e 31 0d 0a 0d 0a}  //weight: 2, accuracy: High
        $x_2_5 = "LookNod^_^" ascii //weight: 2
        $x_1_6 = "Warning: Date Error!" ascii //weight: 1
        $x_2_7 = "Enter StartWork..." ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

