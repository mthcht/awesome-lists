rule Trojan_Win32_SusVbcCompiled_MK_2147970487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusVbcCompiled.MK"
        threat_id = "2147970487"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusVbcCompiled"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vbc.exe" wide //weight: 1
        $x_1_2 = ".vb" wide //weight: 1
        $n_1_3 = "l4896cf8-a4fa-40e9-90e0-3b2ddc3e3ce8" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusVbcCompiled_MK_2147970487_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusVbcCompiled.MK"
        threat_id = "2147970487"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusVbcCompiled"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vbc.exe" wide //weight: 1
        $x_1_2 = "/out:" wide //weight: 1
        $x_1_3 = ".exe" wide //weight: 1
        $n_1_4 = "a4896cf8-a4fa-40e9-90e0-3b2ddc3e3ce4" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

