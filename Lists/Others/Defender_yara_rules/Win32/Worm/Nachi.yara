rule Worm_Win32_Nachi_2147555598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Nachi"
        threat_id = "2147555598"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Nachi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CLSID\\{E6FB5E20-DE35-11CF-9C87-00AA005127ED}\\InProcServer32" ascii //weight: 1
        $x_2_2 = "W3SVC\\Parameters\\Virtual Roots" ascii //weight: 2
        $x_1_3 = "%s /quiet /norestart /o /n" ascii //weight: 1
        $x_1_4 = "Windows2000-KB828749-x86-ENU.exe" ascii //weight: 1
        $x_1_5 = "%s\\drivers\\svchost.exe" ascii //weight: 1
        $x_1_6 = "Select \"DAV:displayname\" from scope()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

