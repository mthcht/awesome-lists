rule Trojan_Win64_CopperhedgeLoader_C_2147971485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CopperhedgeLoader.C!MTB"
        threat_id = "2147971485"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CopperhedgeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8d 43 01 41 30 48 ff 48 63 d8 49 8b c3 48 f7 e3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

