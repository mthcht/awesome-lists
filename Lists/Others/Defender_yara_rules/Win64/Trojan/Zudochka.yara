rule Trojan_Win64_Zudochka_2147753682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zudochka!MTB"
        threat_id = "2147753682"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zudochka"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 45 c7 30 44 0d c8 49 03 cf 48 83 f9 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

