rule HackTool_Linux_Sshscan_B_2147928844_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Sshscan.B"
        threat_id = "2147928844"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Sshscan"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.remoteRun" ascii //weight: 1
        $x_1_2 = "main.main.func1" ascii //weight: 1
        $x_1_3 = "main.remoteRun.func1" ascii //weight: 1
        $x_1_4 = "main.generateIPsRange" ascii //weight: 1
        $x_1_5 = "main.ipAfter" ascii //weight: 1
        $x_1_6 = "main.nextIP" ascii //weight: 1
        $x_1_7 = "main.setupCronJobs" ascii //weight: 1
        $x_1_8 = "main.fetchAndSave" ascii //weight: 1
        $x_1_9 = "main.createProtocolsFileIfNotExists" ascii //weight: 1
        $x_1_10 = "main.execCommand" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

