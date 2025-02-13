rule Backdoor_MSIL_Orcus_A_2147721677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Orcus.A!bit"
        threat_id = "2147721677"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Orcus"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Orcus.Protection" ascii //weight: 1
        $x_1_2 = "Orcus.Plugins" ascii //weight: 1
        $x_1_3 = "Orcus.Native.Shell" ascii //weight: 1
        $x_1_4 = "Orcus.Utilities.KeyLogger" ascii //weight: 1
        $x_1_5 = "Orcus.Commands.RemoteDesktop.Capture" ascii //weight: 1
        $x_1_6 = "Orcus.Commands.DropAndExecute" ascii //weight: 1
        $x_1_7 = "Orcus.Shared.Commands.Webcam" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

