rule Trojan_Win32_Cobalt_AN_2147817808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobalt.AN!MTB"
        threat_id = "2147817808"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobalt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {8d 14 33 8a 04 17 8d 4b 01 83 e1 07 d2 c8 43 88 02 3b 5d fc 7c ea}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobalt_GPA_2147892450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobalt.GPA!MTB"
        threat_id = "2147892450"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobalt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {80 f1 05 80 e9 04 80 f1 03 80 e9 03 88 8c 05}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobalt_AMAA_2147895924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobalt.AMAA!MTB"
        threat_id = "2147895924"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobalt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4d 10 89 c2 83 e2 ?? 8a 14 11 8b 4d 08 32 14 01 88 14 06 40}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

