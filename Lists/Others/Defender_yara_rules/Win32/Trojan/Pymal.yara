rule Trojan_Win32_Pymal_A_2147641818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pymal.A"
        threat_id = "2147641818"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pymal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell\"=\"Explorer.exe,Windows.exe\"" ascii //weight: 1
        $x_1_2 = "whatismyip.com/automation" ascii //weight: 1
        $x_1_3 = "Mozilla\\Firefox\\Profiles" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

