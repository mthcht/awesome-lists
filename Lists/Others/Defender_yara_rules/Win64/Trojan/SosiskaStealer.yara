rule Trojan_Win64_SosiskaStealer_AS_2147982812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SosiskaStealer.AS!MTB"
        threat_id = "2147982812"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SosiskaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 4d c0 80 f1 5b 48 8d 45 97 48 83 7d af 10 48 0f 43 45 97 88 48 09 0f b6 4d c1 80 f1 51 48 8d 45 97 48 83 7d af 10 48 0f 43 45 97 88 48 0a 4c 8d 75 97 48 83 7d af 10 4c 0f 43 75 97 49 8b ce ff 15}  //weight: 1, accuracy: High
        $x_2_2 = {41 0f b6 c7 41 0f b6 d1 41 32 c0 0f b6 c8 80 e2 01 41 0f b6 c7 0f 44 c8 41 0f b6 c0 44 0f b6 f9 02 c0 41 0f b6 c8 c0 f9 07 80 e1 1b 44 0f b6 c1 44 32 c0}  //weight: 2, accuracy: High
        $x_3_3 = {41 0f b6 c0 41 0f b6 d3 41 32 c1 0f b6 c8 80 e2 01 41 0f b6 c0 0f 44 c8 41 0f b6 c1 44 0f b6 c1 02 c0 41 0f b6 c9 c0 f9 07 80 e1 1b 44 0f b6 c9 44 32 c8}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

