rule Trojan_Win32_SuspVolumeShadowCopy_ZPA_2147934401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspVolumeShadowCopy.ZPA"
        threat_id = "2147934401"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspVolumeShadowCopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin" wide //weight: 1
        $x_1_2 = "create shadow /for=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspVolumeShadowCopy_ZPB_2147934403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspVolumeShadowCopy.ZPB"
        threat_id = "2147934403"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspVolumeShadowCopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 00 69 00 73 00 6b 00 73 00 68 00 61 00 64 00 6f 00 77 00 90 00 02 00 0a 00 20 00 2f 00 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspVolumeShadowCopy_ZPB_2147934403_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspVolumeShadowCopy.ZPB"
        threat_id = "2147934403"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspVolumeShadowCopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wmic" wide //weight: 1
        $x_1_2 = "shadowcopy" wide //weight: 1
        $x_1_3 = "call create Volume=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspVolumeShadowCopy_ZPB_2147934403_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspVolumeShadowCopy.ZPB"
        threat_id = "2147934403"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspVolumeShadowCopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mklink" wide //weight: 1
        $x_1_2 = " /D " wide //weight: 1
        $x_1_3 = "\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

