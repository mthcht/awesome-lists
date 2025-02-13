rule Trojan_Win32_Sinimasest_A_2147708075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sinimasest.A!dha"
        threat_id = "2147708075"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinimasest"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "123.exe" ascii //weight: 2
        $x_2_2 = "192.168.88.69" ascii //weight: 2
        $x_1_3 = "%s\\admin$\\system32\\%s" ascii //weight: 1
        $x_1_4 = "In ControlService" ascii //weight: 1
        $x_1_5 = "In CreateFile" ascii //weight: 1
        $x_1_6 = "In CreateService" ascii //weight: 1
        $x_1_7 = "In DeleteFile" ascii //weight: 1
        $x_1_8 = "In DeleteService" ascii //weight: 1
        $x_1_9 = "In QueryServiceStatus" ascii //weight: 1
        $x_1_10 = "In StartService" ascii //weight: 1
        $x_1_11 = "In WriteFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((9 of ($x_1_*))) or
            ((1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

