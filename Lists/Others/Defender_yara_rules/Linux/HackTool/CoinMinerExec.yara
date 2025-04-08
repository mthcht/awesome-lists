rule HackTool_Linux_CoinMinerExec_A_2147938120_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/CoinMinerExec.A"
        threat_id = "2147938120"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "CoinMinerExec"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "sed " wide //weight: 2
        $x_2_2 = ".bashgo" wide //weight: 2
        $x_2_3 = "|pastebin" wide //weight: 2
        $x_2_4 = "|onion" wide //weight: 2
        $x_2_5 = "|bprofr" wide //weight: 2
        $x_2_6 = "|python" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

