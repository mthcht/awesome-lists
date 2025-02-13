rule Backdoor_MSIL_Reomot_A_2147688160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Reomot.A"
        threat_id = "2147688160"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Reomot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_2 = "NetConnection|" ascii //weight: 1
        $x_1_3 = "runshell" ascii //weight: 1
        $x_1_4 = "sendscreen" ascii //weight: 1
        $x_1_5 = "startupenable" ascii //weight: 1
        $x_1_6 = "domelt" ascii //weight: 1
        $x_1_7 = "FloodingJob" ascii //weight: 1
        $x_1_8 = "DestroyWebcam" ascii //weight: 1
        $x_1_9 = "AddWatcher" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Backdoor_MSIL_Reomot_B_2147688167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Reomot.B"
        threat_id = "2147688167"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Reomot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_2 = "runshell" ascii //weight: 1
        $x_1_3 = "sendscreen" ascii //weight: 1
        $x_1_4 = "domelt" ascii //weight: 1
        $x_1_5 = "DestroyWebcam" ascii //weight: 1
        $x_1_6 = "spam" ascii //weight: 1
        $x_1_7 = "Startstresser" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

