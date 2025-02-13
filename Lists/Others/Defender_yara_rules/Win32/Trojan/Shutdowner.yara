rule Trojan_Win32_Shutdowner_L_2147643336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shutdowner.L"
        threat_id = "2147643336"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shutdowner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "attrib +h \"Virus Name.bat" ascii //weight: 1
        $x_1_2 = "Your system is fucked" ascii //weight: 1
        $x_1_3 = "shutdown -s -t 60 -c \"Bye Bye" ascii //weight: 1
        $x_1_4 = "del /f /q C:\\WINDOWS\\system32\\*" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

