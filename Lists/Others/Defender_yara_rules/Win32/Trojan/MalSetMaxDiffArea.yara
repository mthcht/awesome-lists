rule Trojan_Win32_MalSetMaxDiffArea_AA_2147957009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MalSetMaxDiffArea.AA"
        threat_id = "2147957009"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MalSetMaxDiffArea"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ioctl_volsnap_set_max_diff_area_size.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

