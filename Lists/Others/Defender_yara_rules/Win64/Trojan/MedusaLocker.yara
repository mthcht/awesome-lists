rule Trojan_Win64_MedusaLocker_YAC_2147932552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MedusaLocker.YAC!MTB"
        threat_id = "2147932552"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MedusaLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "BabyLockerKZ" wide //weight: 3
        $x_12_2 = {48 8b c3 49 f7 f7 48 8b 06 0f b6 0c 0a 41 32 0c 18 88 0c 03 48 ff c3}  //weight: 12, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

