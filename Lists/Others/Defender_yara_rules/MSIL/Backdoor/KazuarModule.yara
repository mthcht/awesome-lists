rule Backdoor_MSIL_KazuarModule_A_2147968931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/KazuarModule.A!dha"
        threat_id = "2147968931"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KazuarModule"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LeaderAnnouncement" ascii //weight: 1
        $x_1_2 = "ClientAnnouncement" ascii //weight: 1
        $x_1_3 = "LeaderShutdown" ascii //weight: 1
        $x_1_4 = "RequestElection" ascii //weight: 1
        $x_1_5 = "Silence" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

