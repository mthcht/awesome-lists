rule Trojan_Win32_SusVbcCompileTargeted_MK_2147970488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusVbcCompileTargeted.MK"
        threat_id = "2147970488"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusVbcCompileTargeted"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vbc.exe" wide //weight: 1
        $x_1_2 = "/target:" wide //weight: 1
        $x_1_3 = ".vb" wide //weight: 1
        $n_1_4 = "d8896cf8-a4fa-40e9-9070-3b2ddc3e3ce3" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

