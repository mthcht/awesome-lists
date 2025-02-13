rule Trojan_Win32_SuspMasqueradedTool_A_2147768081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspMasqueradedTool.A"
        threat_id = "2147768081"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspMasqueradedTool"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".exe" wide //weight: 1
        $n_1_2 = "avoid_duplicate-{57e35f67-e3d2-4a9e-a645-a92437fdcc9f}" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SuspMasqueradedTool_B_2147768082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspMasqueradedTool.B"
        threat_id = "2147768082"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspMasqueradedTool"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".exe" wide //weight: 1
        $n_1_2 = "avoid_duplicate-{1a088865-e6c3-48e1-bd25-21649db20269}" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

