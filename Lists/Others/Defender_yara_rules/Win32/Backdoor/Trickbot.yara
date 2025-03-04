rule Backdoor_Win32_Trickbot_MAK_2147789465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Trickbot.MAK!MTB"
        threat_id = "2147789465"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "joeboxcontrol.exe" ascii //weight: 1
        $x_1_2 = "joeboxserver.exe" ascii //weight: 1
        $x_1_3 = "Checking process of malware analysis tool: %s" ascii //weight: 1
        $x_5_4 = {8b c7 8b 39 8b f7 c1 e8 [0-1] c1 e6 [0-1] 0b f0 89 32 4b 83 c1 [0-1] 83 c2 [0-1] f6 c3 07 75 e4}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

