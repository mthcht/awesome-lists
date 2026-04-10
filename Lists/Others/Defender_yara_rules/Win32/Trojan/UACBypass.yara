rule Trojan_Win32_UACBypass_NB_2147966733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/UACBypass.NB!MTB"
        threat_id = "2147966733"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "UACBypass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "setting up elevation moniker string..." ascii //weight: 1
        $x_1_2 = "uh oh big boy error in shellexe 0x%08X" ascii //weight: 1
        $x_1_3 = "HOLY FUCKING SHIT IT WORKED" ascii //weight: 1
        $x_2_4 = "An elevated cmd.exe window should have appeared" ascii //weight: 2
        $x_2_5 = "UACBypass" ascii //weight: 2
        $x_2_6 = "masquerading imagepathname and cmdline" ascii //weight: 2
        $x_2_7 = "PEB masquerade complete" ascii //weight: 2
        $x_1_8 = "how marlon fooled the internet: COM elevation..." ascii //weight: 1
        $x_1_9 = "Already running with Administrator privileges" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

