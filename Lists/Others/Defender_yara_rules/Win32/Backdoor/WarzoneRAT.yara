rule Backdoor_Win32_WarzoneRAT_GA_2147771682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/WarzoneRAT.GA!MTB"
        threat_id = "2147771682"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "WarzoneRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\W7H64\\source\\repos\\Ring3 CRAT x64\\Ring3 CRAT x64\\nope.pdb" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_WarzoneRAT_GA_2147771682_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/WarzoneRAT.GA!MTB"
        threat_id = "2147771682"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "WarzoneRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "warzone160" ascii //weight: 1
        $x_1_2 = "[ENTER]" ascii //weight: 1
        $x_1_3 = "[BKSP]" ascii //weight: 1
        $x_1_4 = "[TAB]" ascii //weight: 1
        $x_1_5 = "[CTRL]" ascii //weight: 1
        $x_1_6 = "[ALT]" ascii //weight: 1
        $x_1_7 = "[CAPS]" ascii //weight: 1
        $x_1_8 = "[ESC]" ascii //weight: 1
        $x_1_9 = "[INSERT]" ascii //weight: 1
        $x_1_10 = "AVE_MARIA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_WarzoneRAT_GB_2147777445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/WarzoneRAT.GB!MTB"
        threat_id = "2147777445"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "WarzoneRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "warzoneTURBO" ascii //weight: 1
        $x_1_2 = "[ENTER]" ascii //weight: 1
        $x_1_3 = "[BKSP]" ascii //weight: 1
        $x_1_4 = "[TAB]" ascii //weight: 1
        $x_1_5 = "[CTRL]" ascii //weight: 1
        $x_1_6 = "[ALT]" ascii //weight: 1
        $x_1_7 = "[CAPS]" ascii //weight: 1
        $x_1_8 = "[ESC]" ascii //weight: 1
        $x_1_9 = "[INSERT]" ascii //weight: 1
        $x_1_10 = "AVE_MARIA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

