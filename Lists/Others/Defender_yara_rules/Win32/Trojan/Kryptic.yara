rule Trojan_Win32_Kryptic_AA_2147841589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kryptic.AA!MTB"
        threat_id = "2147841589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kryptic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 04 0f 00 81 ?? ?? ?? ?? 0f b6 b1 ?? ?? ?? ?? 8a 14 0f 0f b6 04 0e 88 04 0f 88 14 0e 0f b6 81 ?? ?? ?? ?? 0f b6 91 ?? ?? ?? ?? 0f b6 04 08 02 04 0a 0f b6 c0 0f b6 04 08 30 83 ?? ?? ?? ?? 43 81 fb ?? ?? ?? ?? 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kryptic_PA_2147842267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kryptic.PA!MTB"
        threat_id = "2147842267"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kryptic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 fe 8b 4d ?? 8a 3c 11 8b 75 ?? 88 3c 31 88 1c 11 0f b6 0c 31 8b 75 ?? 01 f1 81 e1 ff 00 00 00 8b 75 ?? 8b 5d ?? 8a 1c 1e 8b 75 ?? 32 1c 0e 8b 4d ?? 8b 75 ?? 88 1c 31 8b 4d ?? 39 cf 8b 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

