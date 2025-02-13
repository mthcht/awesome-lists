rule HackTool_Linux_BashReverseShellMSF_A_2147767056_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/BashReverseShellMSF.A"
        threat_id = "2147767056"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "BashReverseShellMSF"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "exec(\"aW1wb3J0IHB0eTtwdHkuc3Bhd24oJy9iaW4vc2gnKQ==\".decode(\"base64\"))" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

