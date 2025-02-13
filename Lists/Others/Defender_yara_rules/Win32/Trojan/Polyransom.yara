rule Trojan_Win32_Polyransom_SG_2147907024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Polyransom.SG!MTB"
        threat_id = "2147907024"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Polyransom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {e9 00 00 00 00 32 c2 88 07 ?? ?? ?? ?? ?? ?? 83 f9 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

