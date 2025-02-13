rule Trojan_Win32_Petr_GPA_2147892586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Petr.GPA!MTB"
        threat_id = "2147892586"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Petr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {53 8a 5c 24 08 32 da 83 f1 ea 03 0d ?? ?? 40 00 83 e1 ?? ?? ?? ?? ?? 40 00 33 ca 6b c1 32}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

