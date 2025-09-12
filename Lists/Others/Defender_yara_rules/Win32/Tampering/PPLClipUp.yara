rule Tampering_Win32_PPLClipUp_A_2147952090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Tampering:Win32/PPLClipUp.A"
        threat_id = "2147952090"
        type = "Tampering"
        platform = "Win32: Windows 32-bit platform"
        family = "PPLClipUp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "clipup.exe" wide //weight: 1
        $x_1_2 = " -ppl " wide //weight: 1
        $n_5_3 = ":\\windows\\" wide //weight: -5
        $n_5_4 = ".tmp" wide //weight: -5
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

