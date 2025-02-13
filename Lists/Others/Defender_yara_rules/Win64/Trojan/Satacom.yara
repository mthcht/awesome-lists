rule Trojan_Win64_Satacom_DA_2147918129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Satacom.DA!MTB"
        threat_id = "2147918129"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Satacom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 c1 e9 ?? 33 c8 69 c9 ?? ?? ?? ?? 03 ca 89 4c 95 ?? 8b c1 49 03 d0 49 3b d1 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

