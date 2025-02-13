rule VirTool_Win64_Pentegesz_A_2147919102_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Pentegesz.A!MTB"
        threat_id = "2147919102"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Pentegesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SetupPersistence" ascii //weight: 1
        $x_1_2 = ").RequestCommand" ascii //weight: 1
        $x_1_3 = ").Middleware" ascii //weight: 1
        $x_1_4 = ").CreateFormFile" ascii //weight: 1
        $x_1_5 = ").UploadFile" ascii //weight: 1
        $x_1_6 = ").DownloadFile" ascii //weight: 1
        $x_1_7 = ").ExecAndGetOutput" ascii //weight: 1
        $x_1_8 = ").Hostname" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

