rule Trojan_Win32_SuspCscCompile_A_2147967374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspCscCompile.A"
        threat_id = "2147967374"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspCscCompile"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "csc.exe" wide //weight: 1
        $x_1_2 = "/out:" wide //weight: 1
        $x_1_3 = ".exe" wide //weight: 1
        $x_1_4 = ".cs" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

