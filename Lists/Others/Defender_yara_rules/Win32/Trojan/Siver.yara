rule Trojan_Win32_Siver_A_2147629568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Siver.A"
        threat_id = "2147629568"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Siver"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KeyBoarddll-" ascii //weight: 1
        $x_1_2 = "KeyBoard.dll" ascii //weight: 1
        $x_1_3 = "Searchdll-" ascii //weight: 1
        $x_1_4 = "Search.dll" ascii //weight: 1
        $x_1_5 = "Transitdll-" ascii //weight: 1
        $x_1_6 = "Transit.dll" ascii //weight: 1
        $x_1_7 = "ShareInfectdll-" ascii //weight: 1
        $x_1_8 = "ShareInfect.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

