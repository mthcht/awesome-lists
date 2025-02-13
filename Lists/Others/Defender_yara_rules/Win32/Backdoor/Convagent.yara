rule Backdoor_Win32_Convagent_SRP_2147835599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Convagent.SRP!MTB"
        threat_id = "2147835599"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 55 08 81 c2 9f 04 00 00 89 55 08 8b 45 08 33 d2 b9 4e 01 00 00 f7 f1 89 45 08 66 b9 15 00 66 b8 00 00 66 81 f3 f8 00 66 8b c3 e2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

