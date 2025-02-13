rule HackTool_Win32_Capfetox_A_2147807489_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Capfetox.A!dha"
        threat_id = "2147807489"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Capfetox"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Log4j_Exploit final" ascii //weight: 1
        $x_1_2 = "DnsLog_Url" ascii //weight: 1
        $x_1_3 = "VPS_target" ascii //weight: 1
        $x_1_4 = "Attack" ascii //weight: 1
        $x_1_5 = "nice0e3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

