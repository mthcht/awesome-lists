rule Trojan_Win32_Vimditator_GNA_2147900451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vimditator.GNA!MTB"
        threat_id = "2147900451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vimditator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b cd 8b d1 8d 74 24 ?? 8d 7c 18 ?? 6a 0a c1 e9 ?? f3 a5 8b ca 83 e1 ?? f3 a4 8b 7b ?? 8b 35 ?? ?? ?? ?? 03 fd 89 7b ?? ff d6 6a 0a ff d6 6a 0a ff d6 81 7b ?? 78 da 04 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vimditator_LM_2147957711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vimditator.LM!MTB"
        threat_id = "2147957711"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vimditator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {8b cf 2b d7 0f 1f ?? ?? ?? ?? ?? 8a 04 0a 8d 49 01 32 c3 2a 85 f8 fb ff ff 88 41 ff 83 ee 01}  //weight: 20, accuracy: Low
        $x_10_2 = {0f b7 84 0d 5c e4 ff ff 8d 49 02 66 89 84 0d fa f3 ff ff 66 85 c0 75 ?? 8d 95 fc f3 ff ff 8b f7 8b c2 2b f0 66 0f 1f ?? ?? ?? ?? ?? ?? 0f b7 0a 8d 52 02 66 89 4c 16 fe 66 85 c9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

