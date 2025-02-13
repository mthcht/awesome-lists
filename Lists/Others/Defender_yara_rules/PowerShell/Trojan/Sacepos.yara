rule Trojan_PowerShell_Sacepos_B_2147726149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/Sacepos.B"
        threat_id = "2147726149"
        type = "Trojan"
        platform = "PowerShell: "
        family = "Sacepos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "dl.dropboxusercontent" wide //weight: 1
        $x_1_2 = "dropbox.com/" wide //weight: 1
        $x_10_3 = ".ps1?dl=" wide //weight: 10
        $x_10_4 = {69 00 65 00 78 00 20 00 [0-3] 28 00 6e 00 65 00 77 00 2d 00 6f 00 62 00 6a 00 65 00 63 00 74 00 20 00 6e 00 65 00 74 00 2e 00 77 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00 29 00 2e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 27}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_PowerShell_Sacepos_A_2147726214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/Sacepos.A"
        threat_id = "2147726214"
        type = "Trojan"
        platform = "PowerShell: "
        family = "Sacepos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks /create" wide //weight: 1
        $x_1_2 = "/sc onlogon" wide //weight: 1
        $x_1_3 = "/sc onstart" wide //weight: 1
        $x_1_4 = "/sc onidle" wide //weight: 1
        $x_10_5 = "IEX ((new-object net.webclient).downloadstring('" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_PowerShell_Sacepos_C_2147726248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/Sacepos.C"
        threat_id = "2147726248"
        type = "Trojan"
        platform = "PowerShell: "
        family = "Sacepos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "'https://raw.githubusercontent.com" wide //weight: 1
        $x_1_2 = "http://bit.ly/" wide //weight: 1
        $x_1_3 = "https://pastebin.com/raw" wide //weight: 1
        $x_10_4 = {69 00 65 00 78 00 20 00 [0-3] 28 00 6e 00 65 00 77 00 2d 00 6f 00 62 00 6a 00 65 00 63 00 74 00 20 00 6e 00 65 00 74 00 2e 00 77 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00 29 00 2e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 27}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_PowerShell_Sacepos_D_2147726585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/Sacepos.D"
        threat_id = "2147726585"
        type = "Trojan"
        platform = "PowerShell: "
        family = "Sacepos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 00 65 00 78 00 [0-2] 28 00 5b 00 73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 74 00 65 00 78 00 74 00 2e 00 65 00 6e 00 63 00 6f 00 64 00 69 00 6e 00 67 00 5d 00 3a 00 3a 00 75 00 6e 00 69 00 63 00 6f 00 64 00 65 00 2e 00 67 00 65 00 74 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 5b 00 73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 63 00 6f 00 6e 00 76 00 65 00 72 00 74 00 5d 00 3a 00 3a 00 66 00 72 00 6f 00 6d 00 62 00 61 00 73 00 65 00 36 00 34 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 28 00 67 00 65 00 74 00 2d 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

