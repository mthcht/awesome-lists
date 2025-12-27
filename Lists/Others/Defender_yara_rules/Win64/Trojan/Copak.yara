rule Trojan_Win64_Copak_AHB_2147957500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Copak.AHB!MTB"
        threat_id = "2147957500"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {8a 11 89 ff 4f 81 ef ?? ?? ?? ?? 88 10 43 81 c0 ?? ?? ?? ?? 09 db 81 c7 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 01 ff 29 df 39 f1 7e}  //weight: 30, accuracy: Low
        $x_20_2 = {4a 4a 31 37 01 c0 48 81 c7 ?? ?? ?? ?? 81 ea ?? ?? ?? ?? 81 e8 ?? ?? ?? ?? 81 c0 ?? ?? ?? ?? 39 cf 7c}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

