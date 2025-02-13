rule Trojan_Win32_MpTamperRemdefs_B_2147830252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperRemdefs.B"
        threat_id = "2147830252"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperRemdefs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mpcmdrun" wide //weight: 1
        $x_1_2 = "-removedefinitions -all" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

