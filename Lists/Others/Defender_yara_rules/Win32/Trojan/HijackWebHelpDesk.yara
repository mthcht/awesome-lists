rule Trojan_Win32_HijackWebHelpDesk_A_2147962607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HijackWebHelpDesk.A"
        threat_id = "2147962607"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HijackWebHelpDesk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\cmd.exe" wide //weight: 10
        $x_10_2 = "\\powershell.exe" wide //weight: 10
        $x_10_3 = "\\whoami.exe" wide //weight: 10
        $x_10_4 = "\\net.exe" wide //weight: 10
        $x_10_5 = "\\net1.exe" wide //weight: 10
        $x_10_6 = "\\bitsadmin.exe" wide //weight: 10
        $x_10_7 = "\\wmic.exe" wide //weight: 10
        $x_10_8 = "\\rundll32.exe" wide //weight: 10
        $n_50_9 = "mysqldump" wide //weight: -50
        $n_50_10 = ".bat" wide //weight: -50
        $n_50_11 = "sql92" wide //weight: -50
        $n_50_12 = "frontbase4" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

