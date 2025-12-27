rule Ransom_Win64_FunkSec_CCJT_2147929816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FunkSec.CCJT!MTB"
        threat_id = "2147929816"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FunkSec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "funksecschtasks /create /tn  /tr \"\" /sc onstart" ascii //weight: 2
        $x_1_2 = "Scheduled task created to run ransomware at startup." ascii //weight: 1
        $x_1_3 = "Set-MpPreference -DisableRealtimeMonitoring" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FunkSec_GNM_2147930150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FunkSec.GNM!MTB"
        threat_id = "2147930150"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FunkSec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "funkiydk7c6j3vvck5zk2giml2u746fa5irwalw2kjem6tvofji7rwid.onion" ascii //weight: 1
        $x_1_2 = "device has been successfully infiltrated by funksec ransomware!" ascii //weight: 1
        $x_1_3 = "bc1qrghnt6cqdsxt0qmlcaq0wcavq6pmfm82vtxfeq" ascii //weight: 1
        $x_1_4 = "Do NOT attempt to tamper with files or systems" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FunkSec_MKV_2147955034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FunkSec.MKV!MTB"
        threat_id = "2147955034"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FunkSec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "You have been controlled. Your systems are not secure" ascii //weight: 2
        $x_2_2 = "Hello idiots , we are Ghost Alg" ascii //weight: 2
        $x_3_3 = "darkfunk.pdb" ascii //weight: 3
        $x_1_4 = "Do NOT attempt to trace funksec's activities." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

