rule HackTool_Win32_SecureDelete_A_2147950336_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/SecureDelete.A"
        threat_id = "2147950336"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SecureDelete"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\sb-secure-delete.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

