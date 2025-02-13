rule Trojan_Win64_Cosmu_EC_2147915234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cosmu.EC!MTB"
        threat_id = "2147915234"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cosmu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {a5 32 ab 32 a5 32 a6 32 97 32 9f 32 65 32 64 32 8e 32 9b 32 9f 32 93 32 99 32 97 32 a4 32 97 32 a5 32 60 32}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

