rule Ransom_Win64_Sicarii_YBG_2147961277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Sicarii.YBG!MTB"
        threat_id = "2147961277"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Sicarii"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin delete shadows /all /quiet" wide //weight: 1
        $x_1_2 = "DisableRealtimeMonitoring" wide //weight: 1
        $x_1_3 = "Enter password" wide //weight: 1
        $x_1_4 = "DisableBehaviorMonitoring" wide //weight: 1
        $x_1_5 = "Sicarii.lnk" wide //weight: 1
        $x_1_6 = "files have been encrypted" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

