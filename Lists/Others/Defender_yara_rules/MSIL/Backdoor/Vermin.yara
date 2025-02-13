rule Backdoor_MSIL_Vermin_A_2147728201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Vermin.A!bit"
        threat_id = "2147728201"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vermin"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RunKeyLogger" ascii //weight: 1
        $x_1_2 = "CheckIfProcessIsRunning" ascii //weight: 1
        $x_1_3 = "StartCaptureScreen" ascii //weight: 1
        $x_1_4 = "StartAudioCapture" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

