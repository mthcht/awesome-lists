rule Ransom_Win32_LockyV2_A_2147908905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockyV2.A!MTB"
        threat_id = "2147908905"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockyV2"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 c8 f7 d1 8b 95 ?? ?? ff ff 2b 95 ?? ?? ff ff 81 f2 ?? ?? ?? ?? 0f 31 33 85}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockyV2_B_2147908988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockyV2.B!MTB"
        threat_id = "2147908988"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockyV2"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 d2 66 55 66 5d 8b c8 ff b5 ?? fe ff ff 8f 85 ?? fe ff ff ba ?? ?? ?? ?? 8d 00 0f 31 8d 6d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

