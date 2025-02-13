rule Trojan_Win32_FlowCloudRAT_A_2147892471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlowCloudRAT.A!MTB"
        threat_id = "2147892471"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlowCloudRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b f8 6a 02 6a 00 57 ff d6 57 ff 15 ?? ?? ?? ?? 6a 00 8b d8 6a ?? 57 89 5d fc ff d6 53 ff 15 ?? ?? ?? ?? 57 6a 01 8b f0 53 56 ff 15 ?? ?? ?? ?? 83 c4 38 6a}  //weight: 2, accuracy: Low
        $x_2_2 = {6a 00 68 00 00 04 00 ff 15 ?? ?? ?? ?? 6a 00 8b d8 8b 45 fc 50 56 8b 35 0c 20 00 10 50 6a 00 53 ff d6 8b 3d 10 20 00 10 50 ff d7 50 ff 15 ?? ?? ?? ?? 6a 00 ff 75 fc 6a 00 53 ff d6 50 6a 00 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? ff d7 50 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FlowCloudRAT_B_2147895340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlowCloudRAT.B!MTB"
        threat_id = "2147895340"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlowCloudRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b f8 6a 02 6a 00 57 ff d6 57 ff 15 ?? ?? ?? ?? 6a 00 8b d8 6a ?? 57 89 5d fc ff d6 53 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

