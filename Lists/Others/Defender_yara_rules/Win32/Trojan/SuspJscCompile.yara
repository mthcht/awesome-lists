rule Trojan_Win32_SuspJscCompile_A_2147967371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspJscCompile.A"
        threat_id = "2147967371"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspJscCompile"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jsc.exe" wide //weight: 1
        $x_1_2 = "/out:" wide //weight: 1
        $x_1_3 = ".exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspJscCompile_AM_2147975827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspJscCompile.AM"
        threat_id = "2147975827"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspJscCompile"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jsc.exe" wide //weight: 1
        $x_1_2 = ".js" wide //weight: 1
        $x_1_3 = "aiq_" wide //weight: 1
        $n_1_4 = "abc63e4f-fc7e-4235-8453-2acbbf82fc96" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (2 of ($x*))
}

