rule Trojan_Win64_Bodegun_ABD_2147939881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bodegun.ABD!MTB"
        threat_id = "2147939881"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bodegun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 f1 55 48 8d 7f 01 49 3b d0 73 ?? 48 8d 42 01 48 89 45 bf 48 8d 45 af 49 83 f8 0f 48 0f 47 45 af 88 0c 10 c6 44 10 01 00 eb 0d 44 0f b6 c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bodegun_ARAC_2147959417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bodegun.ARAC!MTB"
        threat_id = "2147959417"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bodegun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {44 8b c0 48 8d 94 24 50 01 00 00 48 8d 4c 24 30 ff 15 ff 3c 00 00 4c 8d 8c 24 40 01 00 00 41 b8 00 80 00 00 48 8d 94 24 50 01 00 00 48 8b cf ff 15 a8 3d 00 00 85 c0 75 bc}  //weight: 2, accuracy: High
        $x_2_2 = {45 33 c9 4c 8b c3 48 8d 15 ?? 40 00 00 33 c9 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

