rule Trojan_Win64_Remus_C_2147967667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Remus.C!MTB"
        threat_id = "2147967667"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Remus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {87 ff 0e 00 0f 10 05 ?? ?? ?? ?? 0f 29 44 24 ?? 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 44 24 ?? c7 44 24 ?? 00 00 00 00 8b 44 24 ?? 83 f8 14 77}  //weight: 5, accuracy: Low
        $x_5_2 = {8b 4c d1 04 4c 89 6c 24 ?? 0f 11 74 24 ?? 48 c7 44 24 ?? 00 00 00 08 48 c7 44 24 ?? 02 00 00 00 41 b9 04 00 00 00 ba 07 00 00 00 4c 8d 44 24 ?? e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

