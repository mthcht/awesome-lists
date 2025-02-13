rule PWS_Win32_Emasen_A_2147687893_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Emasen.A"
        threat_id = "2147687893"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Emasen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {5a 49 50 20 32 20 53 65 63 75 72 65 20 45 58 45 00}  //weight: 6, accuracy: High
        $x_6_2 = {3c 55 6e 7a 69 70 44 69 72 3e 43 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 50 75 62 6c 69 63 20 44 6f 63 75 6d 65 6e 74 5c [0-32] 3c 2f 55 6e 7a 69 70 44 69 72 3e}  //weight: 6, accuracy: Low
        $x_1_3 = "<SetupExe>stap.vbs</SetupExe>" ascii //weight: 1
        $x_1_4 = "<SetupExe>stat.vbs</SetupExe>" ascii //weight: 1
        $x_1_5 = "<SetupExe>sas.vbs</SetupExe>" ascii //weight: 1
        $x_1_6 = "<SetupExe>sac.vbs</SetupExe>" ascii //weight: 1
        $x_1_7 = "<SetupExe>sad.vbs</SetupExe>" ascii //weight: 1
        $x_1_8 = "<SetupExe>kas.vbs</SetupExe>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_6_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

