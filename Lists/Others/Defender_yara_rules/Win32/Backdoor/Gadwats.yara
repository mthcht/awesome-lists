rule Backdoor_Win32_Gadwats_A_2147729222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Gadwats.A"
        threat_id = "2147729222"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Gadwats"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "INSTALL_STARTUP" ascii //weight: 1
        $x_1_2 = "SCREENSHOT" ascii //weight: 1
        $x_1_3 = "RUN_NOSHELL" ascii //weight: 1
        $x_1_4 = "RUN_ASYNC" ascii //weight: 1
        $x_1_5 = "cmd_id" ascii //weight: 1
        $x_1_6 = "[W] Checking mutex, will quit if found..." ascii //weight: 1
        $x_1_7 = "[W] Verifying if mutex is present..." ascii //weight: 1
        $x_1_8 = "[W] Starting agent..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

