rule Backdoor_Win32_FlawedAmmyy_A_2147727848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/FlawedAmmyy.A!bit"
        threat_id = "2147727848"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "FlawedAmmyy"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 76 63 68 c7 45 ?? 6f 73 74 2e c7 45 ?? 65 78 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = "%s\\AMMYY\\wmihost.exe" ascii //weight: 1
        $x_1_3 = "%s\\Microsoft Help\\wsus.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_FlawedAmmyy_C_2147741474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/FlawedAmmyy.C"
        threat_id = "2147741474"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "FlawedAmmyy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "trunk\\ISOmk\\1\\obj\\Release\\1.pdb" ascii //weight: 3
        $x_5_2 = "http://92.38.135.67" wide //weight: 5
        $x_5_3 = "http://27.102.70.196" wide //weight: 5
        $x_5_4 = "http://169.239.128.170" wide //weight: 5
        $x_3_5 = {2f 00 71 00 20 00 2f 00 69 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2f 00}  //weight: 3, accuracy: Low
        $x_1_6 = "C:\\Windows\\System32\\msiexec.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*))) or
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_FlawedAmmyy_GG_2147742094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/FlawedAmmyy.GG!MTB"
        threat_id = "2147742094"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "FlawedAmmyy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 01 89 85 ?? ?? ?? ?? 8b 4d bc c1 e9 ?? 39 8d [0-19] 8b 0c 90 [0-51] 33 95 [0-13] 2d ?? ?? ?? ?? ?? ?? ?? c1 85 ?? ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 33 8d ?? ?? ?? ?? 89 8d ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 89 0c 90 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_FlawedAmmyy_GA_2147742095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/FlawedAmmyy.GA!MTB"
        threat_id = "2147742095"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "FlawedAmmyy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e4 c1 e8 ?? 39 45 [0-9] 8b 04 8a [0-50] 33 [0-23] c1 85 [0-11] 33 [0-11] 8b 4d ?? 8b ?? ?? ?? ?? ?? ?? ?? ?? 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

