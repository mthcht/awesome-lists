rule Trojan_Win32_MPTamperSuspExlc_A_2147812067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MPTamperSuspExlc.A"
        threat_id = "2147812067"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MPTamperSuspExlc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "powershell" wide //weight: 5
        $x_1_2 = "set-mppreference" wide //weight: 1
        $x_1_3 = "add-mppreference" wide //weight: 1
        $x_5_4 = "-exclusionpath" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_MPTamperSuspExlc_C_2147815472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MPTamperSuspExlc.C"
        threat_id = "2147815472"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MPTamperSuspExlc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_1_2 = "set-mppreference" wide //weight: 1
        $x_1_3 = "add-mppreference" wide //weight: 1
        $x_10_4 = "-exclusionpath" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

