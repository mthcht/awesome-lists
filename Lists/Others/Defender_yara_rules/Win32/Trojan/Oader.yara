rule Trojan_Win32_Oader_CG_2147955237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oader.CG!MTB"
        threat_id = "2147955237"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 24 1e 30 c4 04 ?? 32 24 1f 8b 7d ?? 43 83 fb ?? 88 24 0f 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

