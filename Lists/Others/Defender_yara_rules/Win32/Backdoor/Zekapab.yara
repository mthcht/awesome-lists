rule Backdoor_Win32_Zekapab_A_2147712368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zekapab.A!dha"
        threat_id = "2147712368"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zekapab"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 31 31 78 30 30 31 31 30 30 31 31 00}  //weight: 1, accuracy: High
        $x_1_2 = "-DOWNLOAD_END-" ascii //weight: 1
        $x_1_3 = "-DOWNLOAD_START-" ascii //weight: 1
        $x_1_4 = "CMD_EXECUTE" ascii //weight: 1
        $x_1_5 = "DELETE_FILES" ascii //weight: 1
        $x_1_6 = "DELETE_FOLDER" ascii //weight: 1
        $x_1_7 = "DOWNLOAD_DATE" ascii //weight: 1
        $x_2_8 = "FILE_EXECUTE_AND_KiLL_MYSELF" ascii //weight: 2
        $x_1_9 = "KILL_PROCESS" ascii //weight: 1
        $x_1_10 = "REG_GET_KEYS_VALUES" ascii //weight: 1
        $x_1_11 = "UPLOAD_AND_EXECUTE_FILE" ascii //weight: 1
        $x_1_12 = "UPLOAD_FILE" ascii //weight: 1
        $x_1_13 = "/CheckerNow-saMbA-" ascii //weight: 1
        $x_1_14 = "/CheckerSerface" ascii //weight: 1
        $x_1_15 = "/test-Certificates" ascii //weight: 1
        $x_1_16 = "/UpdateCertificate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

