rule HackTool_MacOS_SusCryptoMiner_A_2147775875_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SusCryptoMiner.A"
        threat_id = "2147775875"
        type = "HackTool"
        platform = "MacOS: "
        family = "SusCryptoMiner"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "cgminer" wide //weight: 10
        $x_10_2 = "bfgminer" wide //weight: 10
        $x_10_3 = "multiminer" wide //weight: 10
        $x_10_4 = "macminer" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

