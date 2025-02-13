rule Trojan_Win32_JuiceStealer_G_2147831117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/JuiceStealer.G!MSR"
        threat_id = "2147831117"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "JuiceStealer"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "meta\\meta\\obj\\Release\\netcoreapp3.1\\win-x86\\meta.pdb" ascii //weight: 5
        $x_5_2 = "Chrome\\User Data\\Default\\Login Data" ascii //weight: 5
        $x_5_3 = "System.Net.Requests" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

