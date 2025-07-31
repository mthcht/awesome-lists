rule Trojan_Win32_SusNetExec_MK_2147947975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusNetExec.MK"
        threat_id = "2147947975"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusNetExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sb_" wide //weight: 1
        $x_1_2 = "_bs >nul" wide //weight: 1
        $x_1_3 = "net share & exit" wide //weight: 1
        $x_1_4 = "net localgroup & exit" wide //weight: 1
        $x_1_5 = "net users & exit" wide //weight: 1
        $x_1_6 = "net user & exit" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

