rule Trojan_Win64_Fragtor_A_2147907877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Fragtor.A!MTB"
        threat_id = "2147907877"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 ac fe c8 f6 d8 2c ?? c0 c8 ?? 34 ?? fe c8 88 45}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

