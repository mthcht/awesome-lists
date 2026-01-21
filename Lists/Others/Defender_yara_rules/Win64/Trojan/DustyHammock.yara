rule Trojan_Win64_DustyHammock_GVA_2147961515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DustyHammock.GVA!MTB"
        threat_id = "2147961515"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DustyHammock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a8 01 0f 85 08 01 00 00 49 ff c4 30 da 42 88 14 2e 49 ff c5 4d 89 f8 eb bb 0f 10 45 f0 48 8d 55 b0 0f 29 02 4c 89 6a 10 48 8d bd 18 01 00 00 48 89 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

