rule Backdoor_Win32_CausticDahlia_B_2147957197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/CausticDahlia.B!dha"
        threat_id = "2147957197"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "CausticDahlia"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg_name" ascii //weight: 1
        $x_1_2 = "reg_value" ascii //weight: 1
        $x_1_3 = "reg_cmd" ascii //weight: 1
        $x_1_4 = "text_reg" ascii //weight: 1
        $x_1_5 = "cmd_tmp" ascii //weight: 1
        $x_1_6 = "cur_dir" ascii //weight: 1
        $x_1_7 = "find_data" ascii //weight: 1
        $x_1_8 = "file_op" ascii //weight: 1
        $x_1_9 = "text_shell32" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

