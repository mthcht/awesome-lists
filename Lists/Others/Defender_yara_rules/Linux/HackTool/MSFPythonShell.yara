rule HackTool_Linux_MSFPythonShell_A_2147766167_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/MSFPythonShell.A"
        threat_id = "2147766167"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "MSFPythonShell"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "python" wide //weight: 1
        $x_1_2 = "exec(base64.b64decode" wide //weight: 1
        $x_1_3 = "{2:str,3:lambda b:bytes" wide //weight: 1
        $x_1_4 = "[sys.version_info[0]]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Linux_MSFPythonShell_B_2147766168_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/MSFPythonShell.B"
        threat_id = "2147766168"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "MSFPythonShell"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "python" wide //weight: 5
        $x_5_2 = "exec('aW1wb3J0IHNvY2tld" wide //weight: 5
        $x_1_3 = "c3Rkb3V0X3ZhbHVlKQo='.decode('base64'))" wide //weight: 1
        $x_1_4 = "KHN0ZG91dF92YWx1ZSkK'.decode('base64'))" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Linux_MSFPythonShell_C_2147766169_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/MSFPythonShell.C"
        threat_id = "2147766169"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "MSFPythonShell"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "python" wide //weight: 5
        $x_5_2 = "exec('aW1wb3J0IHNvY2tld" wide //weight: 5
        $x_5_3 = "LmNhbGwoIi9iaW4vYmFzaCIp'.decode('base64'))" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Linux_MSFPythonShell_D_2147767322_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/MSFPythonShell.D"
        threat_id = "2147767322"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "MSFPythonShell"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "python" wide //weight: 5
        $x_5_2 = "exec(__import__('base64').b64decode" wide //weight: 5
        $x_5_3 = "(__import__('codecs').getencoder('utf-8')" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

