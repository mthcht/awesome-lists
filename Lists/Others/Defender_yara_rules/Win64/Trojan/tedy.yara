rule Trojan_Win64_tedy_BMD_2147960760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/tedy.BMD!MTB"
        threat_id = "2147960760"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 63 d0 48 8b 45 ?? 48 01 d0 0f b6 10 8b 45 fc 48 63 c8 48 8b 45 ?? 48 01 c8 83 f2 65 88 10 83 45 fc ?? 8b 45 fc 48 98 48 3b 45 18}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

