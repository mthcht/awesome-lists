rule Trojan_Win64_Havoc_LKI_2147841083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Havoc.LKI!MTB"
        threat_id = "2147841083"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Havoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 10 8b 45 f8 4c 63 c0 48 8b 45 10 4c 01 c0 31 ca 88 10 83 45 fc 01 83 45 f8 01 eb a4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Havoc_AMBB_2147902402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Havoc.AMBB!MTB"
        threat_id = "2147902402"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Havoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {45 31 d1 41 31 c1 44 89 c0 45 01 c0 c0 e8 07 45 31 cf 44 8a 4a fe 41 0f af c4 44 88 7a fd 45 31 d1 44 32 52 ff 41 31 c1 89 c8 01 c9 c0 e8 07 45 31 c8 41 0f af c4 44 88 42 fe 45 89 d0 44 31 c0 31 c1 88 4a ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Havoc_AB_2147903127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Havoc.AB!MTB"
        threat_id = "2147903127"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Havoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b ca 2b 08 01 0b 48 8b 05 ?? ?? ?? ?? 8b 88 ?? ?? ?? ?? 8b 05 ?? ?? ?? ?? 03 ca 05 ?? ?? ?? ?? 41 8b d0 03 c8 c1 ea 08 89 0d ?? ?? ?? ?? 48 63 4b ?? 48 8b 83 ?? ?? ?? ?? 88 14 01 ff 43 ?? 48 8b 05 ?? ?? ?? ?? 8b 08 31 4b ?? 48 8b 0d ?? ?? ?? ?? 8b 41 28 2d ?? ?? ?? ?? 01 81 ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 48 63 53 ?? 48 8b 88 ?? ?? ?? ?? 44 88 04 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Havoc_YAT_2147903376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Havoc.YAT!MTB"
        threat_id = "2147903376"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Havoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 4f 60 41 33 cb 01 4f ?? 48 8b 05 ?? ?? ?? ?? 8b 08 01 0d ?? ?? ?? ?? 48 63 0d ?? ?? ?? ?? 48 8b 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Havoc_AA_2147916018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Havoc.AA!MTB"
        threat_id = "2147916018"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Havoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {64 65 6d 6f 6e 2e 78 36 34 2e 64 6c 6c 00 44 6c 6c 4d 61 69 6e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

