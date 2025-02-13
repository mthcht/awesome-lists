rule Trojan_Win32_Plyromt_2147783681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Plyromt!MSR"
        threat_id = "2147783681"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Plyromt"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://www.blackievirus.com" ascii //weight: 1
        $x_1_2 = "web.status>200 then wscript.quit" ascii //weight: 1
        $x_1_3 = "WINDOWS\\HELP2.VBS" ascii //weight: 1
        $x_1_4 = "shell.run filename" ascii //weight: 1
        $x_1_5 = "web.send" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

