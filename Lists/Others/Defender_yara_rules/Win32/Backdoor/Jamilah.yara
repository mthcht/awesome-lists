rule Backdoor_Win32_Jamilah_A_2147610102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Jamilah.A"
        threat_id = "2147610102"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Jamilah"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "HookedSDT" ascii //weight: 10
        $x_10_2 = "kill Process" ascii //weight: 10
        $x_10_3 = "WriteProcessMemory" ascii //weight: 10
        $x_10_4 = "ZwQuerySystemInformation" ascii //weight: 10
        $x_10_5 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_1_6 = "she is my friend ok" ascii //weight: 1
        $x_1_7 = "I Cant Open My OWN Driver" ascii //weight: 1
        $x_1_8 = "we shouldn't fight each other" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

