rule Trojan_Win32_SuspExfiltration_ZP_2147930702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspExfiltration.ZP"
        threat_id = "2147930702"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspExfiltration"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "tar" wide //weight: 10
        $x_10_2 = ":\\users\\" wide //weight: 10
        $x_2_3 = " -a -c -f " wide //weight: 2
        $x_2_4 = " -acf " wide //weight: 2
        $x_2_5 = " -cf " wide //weight: 2
        $x_1_6 = " -c " wide //weight: 1
        $x_1_7 = " -f " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

