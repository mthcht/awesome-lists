rule Backdoor_Win32_Lianoufa_V_2147755843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lianoufa.V!MTB"
        threat_id = "2147755843"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lianoufa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 4c 05 fb 30 4c 05 fc 48 75}  //weight: 2, accuracy: High
        $x_2_2 = {8a 4c 05 63 30 4c 05 64 48 75}  //weight: 2, accuracy: High
        $x_1_3 = "donotbotherme" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

