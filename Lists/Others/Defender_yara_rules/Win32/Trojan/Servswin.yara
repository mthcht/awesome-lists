rule Trojan_Win32_Servswin_A_2147623110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Servswin.A"
        threat_id = "2147623110"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Servswin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 69 6e 73 65 72 76 69 63 65 73 2e 65 78 65 00 6f 70 65 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "vsollo-eom" ascii //weight: 1
        $x_1_5 = "hh_mm_ss_tt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

