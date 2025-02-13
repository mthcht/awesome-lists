rule HackTool_Linux_Exaramel_A_2147917889_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Exaramel.A"
        threat_id = "2147917889"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Exaramel"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".SetupBeaconInfo" ascii //weight: 1
        $x_1_2 = ".execShell" ascii //weight: 1
        $x_1_3 = ".SetupCrontabPersistence" ascii //weight: 1
        $x_1_4 = ".SetupSystemdPersistence" ascii //weight: 1
        $x_1_5 = "networker.SendReport" ascii //weight: 1
        $x_1_6 = "worker.OSShellExecute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

