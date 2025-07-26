rule Trojan_Win64_DeedRAT_GALA_2147947518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DeedRAT.GALA!MTB"
        threat_id = "2147947518"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DeedRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_8_1 = "vssadmin delete shadows /all /quiet" ascii //weight: 8
        $x_1_2 = "webhooks/YOUR_WEBHOOK_HERE" ascii //weight: 1
        $x_1_3 = "decrypt your files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

