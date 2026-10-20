rule Trojan_Win32_SuspObfusPipeCmd_BA_2147980614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspObfusPipeCmd.BA"
        threat_id = "2147980614"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspObfusPipeCmd"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "201"
        strings_accuracy = "High"
    strings:
        $x_100_1 = " /c " wide //weight: 100
        $x_100_2 = " more " wide //weight: 100
        $x_1_3 = "|c^md" wide //weight: 1
        $x_1_4 = "|cm^d" wide //weight: 1
        $x_1_5 = "|c^m^d" wide //weight: 1
        $x_1_6 = "| c^md" wide //weight: 1
        $x_1_7 = "| cm^d" wide //weight: 1
        $x_1_8 = "| c^m^d" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SuspObfusPipeCmd_BB_2147980615_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspObfusPipeCmd.BB"
        threat_id = "2147980615"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspObfusPipeCmd"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " c^url" wide //weight: 1
        $x_1_2 = " cu^rl" wide //weight: 1
        $x_1_3 = " cur^l" wide //weight: 1
        $x_1_4 = " c^u^rl" wide //weight: 1
        $x_1_5 = " c^ur^l" wide //weight: 1
        $x_1_6 = " cu^r^l" wide //weight: 1
        $x_1_7 = " c^u^r^l" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

