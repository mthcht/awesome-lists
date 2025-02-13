rule VirTool_Win64_Pyrazt_B_2147906325_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Pyrazt.B!MTB"
        threat_id = "2147906325"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Pyrazt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "controllers/executeCommand.go" ascii //weight: 1
        $x_1_2 = "src/controllers.UploadCommand" ascii //weight: 1
        $x_1_3 = "pairat/src/server.go" ascii //weight: 1
        $x_1_4 = "pairat/src/tools/killProccess.go" ascii //weight: 1
        $x_1_5 = "pairat/src/tools/executeNgrok.go" ascii //weight: 1
        $x_1_6 = "net/http.persistConnWriter.Write" ascii //weight: 1
        $x_1_7 = ".socksAuthMethod" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

