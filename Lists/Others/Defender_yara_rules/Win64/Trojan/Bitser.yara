rule Trojan_Win64_Bitser_NB_2147918310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bitser.NB!MTB"
        threat_id = "2147918310"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bitser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 31 c0 50 48 8b 4c 24 48 48 83 ec 28 e8 ?? ?? ?? ?? 48 83 c4 28 48 8b 4c 24 40 48 83 ec 28 e8 ?? ?? ?? ?? 48 83 c4 28 48 8b 4c 24 50 48 83 ec 28 e8 ?? ?? ?? ?? 48 83 c4 28}  //weight: 3, accuracy: Low
        $x_1_2 = "nizhenets.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

