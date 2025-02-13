rule VirTool_Win64_Geshetesz_A_2147901808_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Geshetesz.A!MTB"
        threat_id = "2147901808"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Geshetesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".AuthenticateSheet" ascii //weight: 1
        $x_1_2 = ".AuthenticateDrive" ascii //weight: 1
        $x_1_3 = ".downloadFile" ascii //weight: 1
        $x_1_4 = ".executeCommand" ascii //weight: 1
        $x_1_5 = ".uploadFile" ascii //weight: 1
        $x_1_6 = "addConn" ascii //weight: 1
        $x_1_7 = ".Hostname" ascii //weight: 1
        $x_1_8 = "net/http.persistConnWriter.Write" ascii //weight: 1
        $x_1_9 = ".readSheet" ascii //weight: 1
        $x_1_10 = "shell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

