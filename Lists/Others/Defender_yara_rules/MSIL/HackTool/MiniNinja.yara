rule HackTool_MSIL_MiniNinja_A_2147811733_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/MiniNinja.A!dha"
        threat_id = "2147811733"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MiniNinja"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetBeaconBlackListIP" ascii //weight: 1
        $x_1_2 = "isConnectToListner" ascii //weight: 1
        $x_1_3 = "mybase64_decode" ascii //weight: 1
        $x_1_4 = "MiniPanelHelper.dll" ascii //weight: 1
        $x_1_5 = "BeaconControlServer" ascii //weight: 1
        $x_1_6 = "SendBeaconClientDataToServer" ascii //weight: 1
        $x_1_7 = "DirectConnectToServer" ascii //weight: 1
        $x_1_8 = "BeaconHeartBeat" ascii //weight: 1
        $x_1_9 = "SendServerResponseToBeaconClient" ascii //weight: 1
        $x_1_10 = "HandleBeaconClientRequest" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

