rule Backdoor_Win32_PCview_A_2147636933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PCview.A"
        threat_id = "2147636933"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PCview"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "move /Y \"%s\" \"%s\"" ascii //weight: 1
        $x_2_2 = "Applications\\iexplore.exe\\shell\\open\\command" ascii //weight: 2
        $x_3_3 = "Global\\PCview %d" ascii //weight: 3
        $x_1_4 = "SYSTEM\\CurrentControlSet\\Services\\%s\\Security" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

