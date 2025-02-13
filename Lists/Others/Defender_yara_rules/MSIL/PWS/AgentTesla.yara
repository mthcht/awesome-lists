rule PWS_MSIL_AgentTesla_ZD_2147773174_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/AgentTesla.ZD!MTB"
        threat_id = "2147773174"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_MoveToDocumentEnd" ascii //weight: 1
        $x_1_2 = "get_DeletePreviousWord" ascii //weight: 1
        $x_1_3 = "get_SelectRightByWord" ascii //weight: 1
        $x_1_4 = "get_MoveDownByPage" ascii //weight: 1
        $x_1_5 = "get_DecreaseMicrophoneVolume" ascii //weight: 1
        $x_1_6 = "get_MoveDownByParagraph" ascii //weight: 1
        $x_1_7 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator" ascii //weight: 1
        $x_1_8 = "My.Settings" ascii //weight: 1
        $x_1_9 = "Dispose__Instance__ My.MyWpfExtenstionModule.Windows" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

