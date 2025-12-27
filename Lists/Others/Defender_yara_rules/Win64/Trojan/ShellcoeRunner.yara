rule Trojan_Win64_ShellcoeRunner_PCA_2147947606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcoeRunner.PCA!MTB"
        threat_id = "2147947606"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcoeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 85 f4 07 00 00 0f b6 84 05 b0 03 00 00 32 85 f3 07 00 00 89 c2 48 8b 85 f8 07 00 00 88 10 48 83 85 ?? 07 00 00 01 83 85 ?? 07 00 00 01 8b 85 ?? 07 00 00 3b 85 dc 07 00 00 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcoeRunner_PCB_2147947607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcoeRunner.PCB!MTB"
        threat_id = "2147947607"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcoeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 01 d0 89 ca 88 10 48 8b 95 ?? 07 00 00 48 8b 85 ?? 07 00 00 48 01 d0 0f b6 00 48 8b 8d ?? 07 00 00 48 8b 95 ?? 07 00 00 48 01 ca 32 85 ?? 07 00 00 88 02 48 83 85 ?? 07 00 00 01 48 8b 85 ?? 07 00 00 48 3b 85 ?? 07 00 00 0f 82}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcoeRunner_PCC_2147947612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcoeRunner.PCC!MTB"
        threat_id = "2147947612"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcoeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 98 0f b6 44 05 a0 8b 95 ?? 07 00 00 48 63 ca 48 8b 95 ?? 07 00 00 48 01 ca 32 85 ?? 07 00 00 88 02 83 85 ?? 07 00 00 01 8b 85 ?? 07 00 00 3d 1f 08 00 00 76}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

