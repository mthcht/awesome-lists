rule HackTool_Linux_CymulatRansom_A_2147909893_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/CymulatRansom.A"
        threat_id = "2147909893"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "CymulatRansom"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s/EncryptedFiles" ascii //weight: 1
        $x_1_2 = ".CymCrypt" ascii //weight: 1
        $x_1_3 = "Error: CymulateLinuxRansomware" ascii //weight: 1
        $x_1_4 = "CymulateEDRScenarioExecutor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

