rule Backdoor_Win32_Zbot_C_2147767371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zbot.C!MTB"
        threat_id = "2147767371"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 44 14 28 8b 4c 24 24 32 c8 88 4c 14 28 42 83 fa ?? 72 ec}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 44 0c 0c 2c ?? 88 44 0c 0c 41 83 f9 ?? 72 f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

