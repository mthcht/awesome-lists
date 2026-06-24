rule Trojan_Win64_GachiLoader_SX_2147972209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GachiLoader.SX!MTB"
        threat_id = "2147972209"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GachiLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {0f b6 84 3b ?? ?? ?? ?? 48 8d 5b 01 34 aa 88 44 1d de 48 83 e9 01 75 e8}  //weight: 30, accuracy: Low
        $x_20_2 = {88 41 02 48 8b cb 0f b6 47 03 34 aa 48 83 7b 18 10}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

