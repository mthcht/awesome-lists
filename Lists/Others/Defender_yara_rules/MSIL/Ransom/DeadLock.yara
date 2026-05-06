rule Ransom_MSIL_DeadLock_AB_2147968566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/DeadLock.AB!MTB"
        threat_id = "2147968566"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DeadLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "delete shadows /all /quiet" ascii //weight: 2
        $x_2_2 = "WORM: Infected " ascii //weight: 2
        $x_2_3 = "SpamTelegramAllChats" ascii //weight: 2
        $x_2_4 = "EXFIL: Starting" ascii //weight: 2
        $x_2_5 = "StealChromium" ascii //weight: 2
        $x_2_6 = "got you!" ascii //weight: 2
        $x_2_7 = "WIPER: GPT backup destroyed at LBA" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

