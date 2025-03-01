rule Ransom_Win32_VirLock_RPX_2147905132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/VirLock.RPX!MTB"
        threat_id = "2147905132"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "VirLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 06 90 32 c2 90 88 07 90 42 90 46 90 e9 00 00 00 00 47 90 49}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_VirLock_RPY_2147905133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/VirLock.RPY!MTB"
        threat_id = "2147905133"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "VirLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 06 32 c2 90 88 07 42 90 46 47 90 49 90 83 f9 00 0f 85 e9 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

