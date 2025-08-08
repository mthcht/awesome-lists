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

