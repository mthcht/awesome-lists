rule Trojan_Win32_Pincav_ARA_2147901363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pincav.ARA!MTB"
        threat_id = "2147901363"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pincav"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 82 60 12 40 00 83 f0 d8 88 06 46 42 83 fa 26 75 ee}  //weight: 2, accuracy: High
        $x_2_2 = {30 1a 42 89 c8 03 84 24 6d 01 00 00 39 d0 77 f0}  //weight: 2, accuracy: High
        $x_2_3 = {30 58 ff 40 39 d0 75 f8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pincav_NPC_2147901788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pincav.NPC!MTB"
        threat_id = "2147901788"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pincav"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 94 24 ca 01 00 00 83 c4 0c 8d 8c 24 ?? ?? ?? ?? 8a 84 24 bc 01 00 00 30 42 ?? 42 39 ca 75 f1}  //weight: 5, accuracy: Low
        $x_1_2 = "DeleteFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pincav_AML_2147923108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pincav.AML!MTB"
        threat_id = "2147923108"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pincav"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8a 82 60 12 40 00 83 f0 d8 88 06 46 42 83 fa 26 75 ee}  //weight: 4, accuracy: High
        $x_1_2 = {30 58 ff 40 39 d0 75 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

