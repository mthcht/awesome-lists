rule Trojan_PowerShell_LemonDuck_A_2147777717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/LemonDuck.A"
        threat_id = "2147777717"
        type = "Trojan"
        platform = "PowerShell: "
        family = "LemonDuck"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "schtasks create" wide //weight: 1
        $x_1_2 = "/ru system" wide //weight: 1
        $x_1_3 = "/sc MINUTE /mo" wide //weight: 1
        $x_4_4 = "/tn blackball /F /tr \"blackball\"" wide //weight: 4
        $x_4_5 = "/tn bluetea /F /tr \"bluetea\"" wide //weight: 4
        $x_4_6 = {2f 00 74 00 6e 00 20 00 52 00 74 00 73 00 61 00 [0-2] 20 00 2f 00 46 00 20 00 2f 00 74 00 72 00 20 00 22 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 3 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_PowerShell_LemonDuck_B_2147777719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/LemonDuck.B"
        threat_id = "2147777719"
        type = "Trojan"
        platform = "PowerShell: "
        family = "LemonDuck"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell -w" wide //weight: 1
        $x_1_2 = "hidden" wide //weight: 1
        $x_1_3 = "[System.Text.Encoding]::ASCII.GetString" wide //weight: 1
        $x_3_4 = {2e 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 44 00 61 00 74 00 61 00 28 00 27 00 68 00 74 00 74 00 70 00 [0-48] 2f 00 61 00 2e 00 6a 00 73 00 70 00 3f 00}  //weight: 3, accuracy: Low
        $x_1_5 = "$env:COMPUTERNAME,$env:USERNAME" wide //weight: 1
        $x_1_6 = "(get-wmiobject Win32_ComputerSystemProduct).UUID" wide //weight: 1
        $x_1_7 = "(random))-join'*'))" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

