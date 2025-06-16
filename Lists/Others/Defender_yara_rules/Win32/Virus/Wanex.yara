rule Virus_Win32_Wanex_EH_2147943765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Wanex.EH!MTB"
        threat_id = "2147943765"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Wanex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "The Last Goodbye" ascii //weight: 1
        $x_1_2 = "MyDoom infected" ascii //weight: 1
        $x_1_3 = "PewkBot" ascii //weight: 1
        $x_1_4 = "Computers Infected" ascii //weight: 1
        $x_1_5 = "Files Infected" ascii //weight: 1
        $x_1_6 = "You_are_a_wanker.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

