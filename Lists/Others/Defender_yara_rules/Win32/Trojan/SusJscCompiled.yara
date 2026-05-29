rule Trojan_Win32_SusJscCompiled_MK_2147970492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusJscCompiled.MK"
        threat_id = "2147970492"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusJscCompiled"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jsc.exe" wide //weight: 1
        $x_1_2 = ".js" wide //weight: 1
        $n_1_3 = "h4896cf8-a4fa-40e9-90e0-3b2ddc3e3ce2" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusJscCompiled_MK_2147970492_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusJscCompiled.MK"
        threat_id = "2147970492"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusJscCompiled"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jsc.exe" wide //weight: 1
        $x_1_2 = "/out:" wide //weight: 1
        $x_1_3 = ".exe" wide //weight: 1
        $n_1_4 = "74896cf8-a4fa-40e9-90e0-3b2ddc3e3ce6" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

