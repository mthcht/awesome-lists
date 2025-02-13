rule Trojan_Win32_Gamarue_CCFO_2147899673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gamarue.CCFO!MTB"
        threat_id = "2147899673"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamarue"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 44 11 b0 83 f0 ?? 88 45 ef 0f b7 8d ?? fe ff ff 0f b6 95 ?? fe ff ff 03 ca 83 e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

