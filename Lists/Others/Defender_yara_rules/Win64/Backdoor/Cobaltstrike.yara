rule Backdoor_Win64_Cobaltstrike_AX_2147908031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Cobaltstrike.AX!MTB"
        threat_id = "2147908031"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 0f b6 41 01 45 0f b6 01 49 63 ca 41 ff c2 4c 0f af c3 4c 03 c0 49 8b c7 48 ff cb 48 f7 e1 4d 0f af c3 48 8b c1 48 2b c2 49 ff c3 48 d1 e8 48 03 c2 48 c1 e8 04 48 6b c0 ?? 48 2b c8 0f b6 44 0d ?? 43 30 04 20 41 81 fa ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {43 0f b6 04 0b 49 63 ca 41 ff c2 4d 8d 5b 01 4c 69 c0 ?? ?? ?? ?? 41 0f b6 01 49 ff c8 4c 0f af c0 48 8b c6 48 f7 e1 [0-48] 48 2b c8 0f b6 44 ?? ?? 43 30 44 18 ff 41 81 fa ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

