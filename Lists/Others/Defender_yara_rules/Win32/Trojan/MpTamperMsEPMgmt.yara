rule Trojan_Win32_MpTamperMsEPMgmt_A_2147779966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperMsEPMgmt.A"
        threat_id = "2147779966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperMsEPMgmt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\msiexec.exe" wide //weight: 3
        $x_3_2 = "{942ea1ec-7391-4abd-9524-388bc2d70673}" wide //weight: 3
        $x_2_3 = "/x" wide //weight: 2
        $x_2_4 = "/uninstall" wide //weight: 2
        $x_1_5 = "/quiet" wide //weight: 1
        $x_1_6 = "/qn" wide //weight: 1
        $x_1_7 = "norestart" wide //weight: 1
        $x_1_8 = "forcerestart" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

