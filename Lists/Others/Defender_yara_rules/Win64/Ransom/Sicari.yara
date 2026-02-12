rule Ransom_Win64_Sicari_MX_2147962957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Sicari.MX!MTB"
        threat_id = "2147962957"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Sicari"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".sicarii" ascii //weight: 1
        $x_1_2 = "vssadmin delete shadows /all /quiet" ascii //weight: 1
        $x_1_3 = "your files have been encrypted" ascii //weight: 1
        $x_1_4 = "DisableAntiSpyware" ascii //weight: 1
        $x_1_5 = "DisableRealtimeMonitoring" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

