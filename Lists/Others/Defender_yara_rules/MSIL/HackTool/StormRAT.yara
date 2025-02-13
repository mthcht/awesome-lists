rule HackTool_MSIL_StormRAT_2147688712_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/StormRAT"
        threat_id = "2147688712"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StormRAT"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\STR\\" wide //weight: 1
        $x_1_2 = "Keylogs|" wide //weight: 1
        $x_1_3 = "NextPartOfUpload|" wide //weight: 1
        $x_1_4 = "Download+Execute" wide //weight: 1
        $x_1_5 = "MyInfo|" wide //weight: 1
        $x_1_6 = "StartWebcam" wide //weight: 1
        $x_1_7 = "StartKeystrokeCapture" wide //weight: 1
        $x_1_8 = "RemoteDesktop|" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

