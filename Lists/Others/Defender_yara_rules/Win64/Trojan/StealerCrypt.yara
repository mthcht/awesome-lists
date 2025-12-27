rule Trojan_Win64_StealerCrypt_PSW_2147953080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StealerCrypt.PSW!MTB"
        threat_id = "2147953080"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StealerCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 8d 04 17 41 3b c5 73 56 48 8d 44 06 10 41 8b d2 0f b6 54 17 10 30 10 41 ff c2 44 3b d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

