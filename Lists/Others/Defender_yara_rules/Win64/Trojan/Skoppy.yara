rule Trojan_Win64_Skoppy_B_2147941823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Skoppy.B!dha"
        threat_id = "2147941823"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Skoppy"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\\\.\\VBoxMiniRdrDN" ascii //weight: 2
        $x_2_2 = "SOFTWARE\\VMware, Inc.\\VMware Tools" ascii //weight: 2
        $x_4_3 = "co_sys_co_" ascii //weight: 4
        $x_4_4 = "%s\\micro.log.zip" ascii //weight: 4
        $x_8_5 = "cmd /c schtasks /create /tn \"CleanSyslogTask\" /tr \"rundll32 %s,s\"" ascii //weight: 8
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((2 of ($x_4_*))) or
            ((1 of ($x_8_*))) or
            (all of ($x*))
        )
}

