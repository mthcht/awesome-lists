rule Trojan_Win64_Radthief_MR_2147948866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Radthief.MR!MTB"
        threat_id = "2147948866"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Radthief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {c0 2e 74 68 65 6d 69 64 61 00 ?? ?? 00 00 70 09 ?? ?? ?? ?? ?? ?? 42 06}  //weight: 3, accuracy: Low
        $x_2_2 = {60 20 20 20 20 20 20 20 20 44 65 05 00 00 e0 02 00 00 34 04 00 00 86 01}  //weight: 2, accuracy: High
        $x_5_3 = {c0 20 20 20 20 20 20 20 20 98 69 00 00 00 f0 08 00 00 32 00 00 00 0e 06}  //weight: 5, accuracy: High
        $x_5_4 = {40 00 00 c0 2e 74 68 65 6d 69 64 61 ?? ?? ?? ?? ?? 70 09 ?? ?? ?? ?? ?? ?? 42 06}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Radthief_KK_2147951993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Radthief.KK!MTB"
        threat_id = "2147951993"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Radthief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {49 89 d0 48 f7 e9 48 01 ca 48 d1 fa 49 89 c9 48 c1 f9 ?? 48 29 ca 48 8d 14 52 4d 89 ca 49 29 d1 49 39 f0}  //weight: 20, accuracy: Low
        $x_10_2 = {49 89 d0 48 f7 ea 48 c1 fa ?? 48 69 d2 ?? ?? 00 00 4d 89 c1 49 29 d0 49 8d 90 ?? ?? 00 00 48 39 d1}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

