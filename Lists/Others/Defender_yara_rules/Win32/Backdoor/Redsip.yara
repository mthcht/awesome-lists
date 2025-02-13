rule Backdoor_Win32_Redsip_A_2147653707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Redsip.A"
        threat_id = "2147653707"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Redsip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CMD_File_RUN_HIDE" wide //weight: 1
        $x_1_2 = "CMD_FILE_UPLOAD" wide //weight: 1
        $x_1_3 = "CMD_File_FIND" wide //weight: 1
        $x_1_4 = "SHELL_CMD" wide //weight: 1
        $x_1_5 = "ProcFileUpload" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

