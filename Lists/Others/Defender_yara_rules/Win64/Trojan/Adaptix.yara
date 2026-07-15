rule Trojan_Win64_Adaptix_ABTS_2147973598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Adaptix.ABTS!MTB"
        threat_id = "2147973598"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Adaptix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {49 8b c0 48 8d 15 ?? ?? ?? ?? 83 e0 0f 49 ff c0 8a 04 10 30 01 48 ff c1 49 83 e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

