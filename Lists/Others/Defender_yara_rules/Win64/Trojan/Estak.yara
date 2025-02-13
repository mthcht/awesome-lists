rule Trojan_Win64_Estak_EB_2147837770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Estak.EB!MTB"
        threat_id = "2147837770"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Estak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {89 c8 48 0f af c0 31 d2 49 f7 f6 b8 fb ff ff ff 29 d0 81 f9 fe ff ff 7f 0f 42 c2 89 c1 83 e1 0f 8a 84 0c a0 00 00 00 88 04 1f 48 ff c7 e9 ab fe ff ff}  //weight: 8, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

