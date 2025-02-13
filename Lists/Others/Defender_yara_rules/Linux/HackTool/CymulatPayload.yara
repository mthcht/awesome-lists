rule HackTool_Linux_CymulatPayload_A_2147909894_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/CymulatPayload.A"
        threat_id = "2147909894"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "CymulatPayload"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CymulateEDRScenarioExecutor" ascii //weight: 1
        $x_1_2 = "attack_id" ascii //weight: 1
        $x_1_3 = "scenario_id" ascii //weight: 1
        $x_1_4 = "%s/global_apt_scenarios_output.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

