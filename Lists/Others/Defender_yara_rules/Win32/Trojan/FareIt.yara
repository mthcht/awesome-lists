rule Trojan_Win32_FareIt_Delf_2147787476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FareIt.Delf!MTB"
        threat_id = "2147787476"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FareIt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 86 bc 00 00 00 8b 8e c0 00 00 00 69 c0 84 00 00 00 8b 95 dc fd ff ff 89 94 08 80 00 00 00 8b 86 bc 00 00 00 69 c0 84 00 00 00 03 86 c0 00 00 00 8d 8d f8 fd ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FareIt_VGTR_2147794108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FareIt.VGTR!MTB"
        threat_id = "2147794108"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FareIt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 5f 41 41 35 4e 85 4d b1 3a 25 78 41 41 d6 be b6 be be 33 3b 1e 4b 41 41}  //weight: 1, accuracy: High
        $x_1_2 = "IDesignerHook@VA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FareIt_HGFT_2147794612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FareIt.HGFT!MTB"
        threat_id = "2147794612"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FareIt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c7 0f ef d3 66 0f fc fe 0f 64 cd 0f fd e3 0f 71 f7 db 66 0f fc f2 f3 a4 66 0f dc cd 0f f9 d4 fc 0f fa e5 66 0f e1 cb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

