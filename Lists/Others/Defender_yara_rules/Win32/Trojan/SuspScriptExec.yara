rule Trojan_Win32_SuspScriptExec_C_2147965443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspScriptExec.C"
        threat_id = "2147965443"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspScriptExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ").b64decode(" wide //weight: 1
        $x_1_2 = ").decode(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

