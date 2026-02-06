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

rule Ransom_Win64_Sicarii_AHB_2147962553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Sicarii.AHB!MTB"
        threat_id = "2147962553"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Sicarii"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "infect_id" ascii //weight: 10
        $x_20_2 = "README_SICARII_LOCKED.txt" ascii //weight: 20
        $x_30_3 = "net user Sicarius" ascii //weight: 30
        $x_40_4 = "aws iam create-user --user-name Sicarius" ascii //weight: 40
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

