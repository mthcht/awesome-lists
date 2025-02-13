rule Backdoor_Win32_Hera_A_2147735014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hera.A!bit"
        threat_id = "2147735014"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hera"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hera::bi::Controller::RunApp" ascii //weight: 1
        $x_1_2 = "RunHideProcessModule" ascii //weight: 1
        $x_1_3 = "check_run_memory_module_interface" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

