rule HackTool_Python_TerseAmplitude_B_2147982497_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Python/TerseAmplitude.B!dha"
        threat_id = "2147982497"
        type = "HackTool"
        platform = "Python: Python scripts"
        family = "TerseAmplitude"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Copy Selected IP:PORT" ascii //weight: 1
        $x_1_2 = "Copy Selected IP(s)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

