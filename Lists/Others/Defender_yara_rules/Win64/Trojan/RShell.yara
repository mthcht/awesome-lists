rule Trojan_Win64_RShell_AHB_2147946221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RShell.AHB!MTB"
        threat_id = "2147946221"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 8d 3d 13 45 00 00 48 89 54 24 40 4c 89 44 24 38 48 8d 54 24 51 4c 89 44 24 30 45 31 c0 44 89 4c 24 28 45 31 c9 48 89 7c 24 48 c7 44 24 20 01 00 00 00 ff 15}  //weight: 3, accuracy: High
        $x_2_2 = {c7 05 6c 45 00 00 68 00 00 00 c7 05 9e 45 00 00 01 01 00 00 48 89 05 bb 45 00 00 48 89 05 ac 45 00 00 48 89 05 9d 45 00 00 48 b8 ?? ?? ?? ?? ?? ?? ?? 00 48 89 44 24 51}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RShell_AHA_2147969392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RShell.AHA!MTB"
        threat_id = "2147969392"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = "\\\\.\\pipe\\rshell_handover_%s" ascii //weight: 20
        $x_30_2 = {89 ca c1 e2 ?? 29 ca 29 d0 89 c1 89 c8 0f b6 c0 c1 e0 ?? 09 c6 41 89 f1 8b 85 e0}  //weight: 30, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

