rule Trojan_Win32_MalVssadminShadowCopyDel_AA_2147957010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MalVssadminShadowCopyDel.AA"
        threat_id = "2147957010"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MalVssadminShadowCopyDel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin" wide //weight: 1
        $x_1_2 = "delete" wide //weight: 1
        $x_1_3 = "shadows" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

