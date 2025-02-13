rule Trojan_Win32_Tenpoj_A_2147744742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tenpoj.A!MSR"
        threat_id = "2147744742"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tenpoj"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.123456abcgsdwere56463455345435435657222222.com" ascii //weight: 1
        $x_1_2 = "rundll32.exe %s startwork" ascii //weight: 1
        $x_1_3 = "Documents\\Visual Studio 2008\\Projects\\vpnet_dll\\Release\\vpnet_dll.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

