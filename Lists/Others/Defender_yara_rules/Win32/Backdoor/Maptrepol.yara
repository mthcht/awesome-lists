rule Backdoor_Win32_Maptrepol_A_2147712221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Maptrepol.A"
        threat_id = "2147712221"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Maptrepol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ms_com_hzyf_microsoft_app_com_1.0" wide //weight: 2
        $x_2_2 = "clas_hzy_apt_winmmt_x_0.0.01" wide //weight: 2
        $x_1_3 = "wrlck.cab" ascii //weight: 1
        $x_1_4 = "%lsmsattrib32_%s_i" ascii //weight: 1
        $x_1_5 = "wndplyr.cab" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

