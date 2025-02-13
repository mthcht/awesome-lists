rule Backdoor_MSIL_Cooatut_A_2147687565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Cooatut.A"
        threat_id = "2147687565"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cooatut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Cloud Net" wide //weight: 1
        $x_1_2 = "GetRootDir" ascii //weight: 1
        $x_1_3 = "KeyStrokeMonitor" ascii //weight: 1
        $x_1_4 = "MalwareRemover" ascii //weight: 1
        $x_1_5 = "HeuristicScan" ascii //weight: 1
        $x_1_6 = "StartStressor" ascii //weight: 1
        $x_1_7 = "UploadAndExecute" ascii //weight: 1
        $x_1_8 = "BlockWebsite" ascii //weight: 1
        $x_1_9 = "RunCam" ascii //weight: 1
        $x_1_10 = "RunLoop" ascii //weight: 1
        $x_1_11 = "RemoteAudio" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

