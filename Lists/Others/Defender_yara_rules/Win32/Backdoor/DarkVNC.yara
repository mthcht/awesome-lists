rule Backdoor_Win32_DarkVNC_A_2147772193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/DarkVNC.A!MTB"
        threat_id = "2147772193"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkVNC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe c0 83 f0 ?? 88 44 24 ?? 8b 44 24 ?? 04 02 83 f0 ?? 88 44 24 ?? 8b 44 24 ?? 04 03 83 f0 ?? 88 44 24}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 44 14 1c 8b 4c 24 18 02 ca 0f be c0 33 c8 88 4c 14 1c 42 83 fa 0d 72}  //weight: 1, accuracy: High
        $x_1_3 = "muuuutex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_DarkVNC_GHN_2147845224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/DarkVNC.GHN!MTB"
        threat_id = "2147845224"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkVNC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {57 54 53 51 c7 44 24 ?? 75 65 72 79 c7 44 24 ?? 53 65 73 73 c7 44 24 ?? 69 6f 6e 49 c7 44 24 ?? 6e 66 6f 72 c7 44 24 ?? 6d 61 74 69 c7 44 24 ?? 6f 6e 57 00 ff d6}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 4c 24 04 68 07 80 00 00 8b 41 04 8a 40 01 32 01 2c 12 a2}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

