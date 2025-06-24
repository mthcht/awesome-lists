rule Trojan_Win64_RedCap_ARA_2147897875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RedCap.ARA!MTB"
        threat_id = "2147897875"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RedCap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "1BlueDashUpdate.cmd" ascii //weight: 2
        $x_2_2 = "DecryptFileA" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RedCap_MKC_2147944544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RedCap.MKC!MTB"
        threat_id = "2147944544"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RedCap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 e7 8b c7 2b c2 d1 e8 03 c2 c1 e8 05 0f b7 c0 6b c8 38 0f b7 c7 41 03 fe 66 2b c1 66 41 03 c5 66 31 06 48 8d 76 ?? 83 ff 0b 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

