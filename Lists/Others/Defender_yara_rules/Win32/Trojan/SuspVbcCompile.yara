rule Trojan_Win32_SuspVbcCompile_A_2147967373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspVbcCompile.A"
        threat_id = "2147967373"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspVbcCompile"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vbc.exe" wide //weight: 1
        $x_1_2 = "/out:" wide //weight: 1
        $x_1_3 = ".exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

