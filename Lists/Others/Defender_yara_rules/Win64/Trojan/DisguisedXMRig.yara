rule Trojan_Win64_DisguisedXMRig_MA_2147970169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DisguisedXMRig.MA!MTB"
        threat_id = "2147970169"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DisguisedXMRig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "XMRIG_EXE" ascii //weight: 10
        $x_5_2 = "Microsoft\\Windows Defender\\Exclusions\\Paths" ascii //weight: 5
        $x_5_3 = "Microsoft\\Windows Defender\\Exclusions\\Extensions" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

