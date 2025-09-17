rule Trojan_Win64_Maranhao_GAS_2147952370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Maranhao.GAS!MTB"
        threat_id = "2147952370"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Maranhao"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_8_1 = "api.maranhaogang.fun" ascii //weight: 8
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

