rule Backdoor_Win32_Hanuman_AHA_2147959712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hanuman.AHA!MTB"
        threat_id = "2147959712"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hanuman"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 45 f8 50 8d 45 e4 50 ff 75 f4 e8 ?? ?? ?? ?? 89 45 fc 83 f8 ff 0f 84 d4 00 00 00 ff 05 ?? 30 40 00 ff 35 ?? 30 40 00 68 25 31 40 00 68 00 20 40 00 e8 ?? ?? ?? ?? 83 c4 0c 6a 00 6a 42 68 38 30 40 00 ff 75 fc e8}  //weight: 2, accuracy: Low
        $x_1_2 = "Hanuman Server [DOS SHELL DAEMON]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

