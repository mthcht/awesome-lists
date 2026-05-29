rule Trojan_Win32_SusIlasmCompiled_MK_2147970493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusIlasmCompiled.MK"
        threat_id = "2147970493"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusIlasmCompiled"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ilasm" wide //weight: 1
        $x_1_2 = ".il" wide //weight: 1
        $n_1_3 = "i4896cf8-a4fa-40e9-90e0-3b2ddc3e3cem" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

