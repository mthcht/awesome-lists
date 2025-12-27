rule HackTool_Win32_PossibleActiveDirectoryDumping_A_2147950213_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/PossibleActiveDirectoryDumping.A"
        threat_id = "2147950213"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PossibleActiveDirectoryDumping"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ldifde" wide //weight: 1
        $x_1_2 = " -f " wide //weight: 1
        $n_10_3 = " -i " wide //weight: -10
        $n_10_4 = " -s " wide //weight: -10
        $n_10_5 = " -c " wide //weight: -10
        $n_10_6 = " -p " wide //weight: -10
        $n_10_7 = " -g " wide //weight: -10
        $n_10_8 = " -m " wide //weight: -10
        $n_10_9 = " -n " wide //weight: -10
        $n_10_10 = " -a " wide //weight: -10
        $n_10_11 = " -b " wide //weight: -10
        $n_10_12 = " -u " wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

