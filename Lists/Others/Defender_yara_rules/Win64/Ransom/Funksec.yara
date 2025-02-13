rule Ransom_Win64_Funksec_GA_2147929878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Funksec.GA!MTB"
        threat_id = "2147929878"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Funksec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your organization, device has been successfully infiltrated by funksec ransomware!" ascii //weight: 1
        $x_1_2 = "README-.md" ascii //weight: 1
        $x_3_3 = ".funksec" ascii //weight: 3
        $x_1_4 = "**Ransom Details**" ascii //weight: 1
        $x_1_5 = "bc1qrghnt6cqdsxt0qmlcaq0wcavq6pmfm82vtxfeq" ascii //weight: 1
        $x_1_6 = "funkiydk7c6j3vvck5zk2giml2u746fa5irwalw2kjem6tvofji7rwid.onion" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

