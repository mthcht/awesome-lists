rule Trojan_Win32_MpTamperCfgAcl_B_2147765983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperCfgAcl.B"
        threat_id = "2147765983"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperCfgAcl"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "software\\microsoft\\windows defender" wide //weight: 3
        $x_1_2 = " -on " wide //weight: 1
        $x_1_3 = " -ot " wide //weight: 1
        $x_1_4 = " reg " wide //weight: 1
        $x_1_5 = " -actn " wide //weight: 1
        $x_1_6 = " setowner " wide //weight: 1
        $x_1_7 = " -ownr " wide //weight: 1
        $x_1_8 = " ace " wide //weight: 1
        $x_1_9 = " -ace " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

