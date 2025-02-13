rule VirTool_Win32_Pyrazt_A_2147808499_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Pyrazt.A!MTB"
        threat_id = "2147808499"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Pyrazt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "controllers/executeCommand.go" ascii //weight: 1
        $x_1_2 = "src/controllers.UploadCommand" ascii //weight: 1
        $x_1_3 = "pairat/pairat/src/server.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

