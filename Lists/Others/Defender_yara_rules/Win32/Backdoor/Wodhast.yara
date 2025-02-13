rule Backdoor_Win32_Wodhast_A_2147710792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Wodhast.A"
        threat_id = "2147710792"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Wodhast"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LL_STARTUP" ascii //weight: 1
        $x_1_2 = "T_PROP" ascii //weight: 1
        $x_1_3 = "[W] Mutex" ascii //weight: 1
        $x_1_4 = "cmd_id" ascii //weight: 1
        $x_1_5 = "screenshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

