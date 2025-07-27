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

