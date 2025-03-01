rule Trojan_Win64_Dbadur_GCM_2147929128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dbadur.GCM!MTB"
        threat_id = "2147929128"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dbadur"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {32 f1 4e 12 76 ?? 20 41 76 ?? 20 41 76 ?? 20 41 7f e8 ?? ?? ?? ?? 20 41 24 e5 25 40 6e ?? 20 41 24 e5 24 40 7c ?? 20 41 24 e5 23}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

