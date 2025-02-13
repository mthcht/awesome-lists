rule VirTool_Win32_Hercules_G_2147742833_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Hercules.G!MTB"
        threat_id = "2147742833"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Hercules"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "syscall.connect" ascii //weight: 2
        $x_2_2 = "EGESPLOIT" ascii //weight: 2
        $x_2_3 = "This program can only be run on processors with MMX support" ascii //weight: 2
        $x_2_4 = {84 00 8b 05 68 ?? ?? 00 90 8b 0d ?? ?? ?? 00 90 89 04 24 c7 44 24 04 00 00 00 00 c7 44 24 08 00 00 00 00 89 4c 24 0c 8b 44 24 2c 89 44 24 10 c7 44 24 14 00 00 00 00 c7 44 24 18 00 00 00 00 e8 73 05 00 00 8b 44 24 1c 85 c0 74 16 8b 0d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

