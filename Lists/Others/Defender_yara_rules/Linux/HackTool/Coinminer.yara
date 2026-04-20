rule HackTool_Linux_Coinminer_TS8_2147967316_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Coinminer.TS8"
        threat_id = "2147967316"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Coinminer"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kryptex.network" ascii //weight: 1
        $x_1_2 = "xmr " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

