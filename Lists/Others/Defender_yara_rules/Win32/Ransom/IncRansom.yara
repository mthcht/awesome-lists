rule Ransom_Win32_IncRansom_YAA_2147852703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/IncRansom.YAA!MTB"
        threat_id = "2147852703"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "IncRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Wallpaper" wide //weight: 1
        $x_1_2 = "INC-README" wide //weight: 1
        $x_1_3 = "background-image.jpg" wide //weight: 1
        $x_1_4 = "SW5jLiBSYW5zb213YXJlDQoNCldlIGhhdmUgaGFja2VkIHlvdSBhbmQg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_IncRansom_YAF_2147918524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/IncRansom.YAF!MTB"
        threat_id = "2147918524"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "IncRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 b4 99 be 1e 00 00 00 f7 fe 0f be 92 ?? ?? ?? ?? 33 ca 8b 45 a4 03 45 b4 88 08 eb 8a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

