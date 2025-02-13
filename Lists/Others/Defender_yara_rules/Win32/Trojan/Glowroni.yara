rule Trojan_Win32_Glowroni_2147644781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glowroni"
        threat_id = "2147644781"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glowroni"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "muboeegy" ascii //weight: 2
        $x_2_2 = "maskeroni.co.uk" ascii //weight: 2
        $x_1_3 = "CurrentVersion\\Winlogon\\Notify\\" ascii //weight: 1
        $x_1_4 = "SYSTEM\\CurrentControlSet\\Services\\ccEvtMgr" ascii //weight: 1
        $x_2_5 = "joincgui.dll" ascii //weight: 2
        $x_2_6 = "glowext.dll" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

