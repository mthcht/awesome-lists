rule Trojan_Win64_Mekotio_MCH_2147928189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mekotio.MCH!MTB"
        threat_id = "2147928189"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mekotio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UVw8YCmZ9vntF9Bt5GhH/-rT6jBCOAXech5H5OiuW" ascii //weight: 1
        $x_1_2 = "Injectmoduleconseito" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

