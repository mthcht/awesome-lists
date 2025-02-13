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

