rule HackTool_Linux_Eggshell_A_2147798580_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Eggshell.A"
        threat_id = "2147798580"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Eggshell"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "python" wide //weight: 2
        $x_10_2 = "/tmp/espl.py" wide //weight: 10
        $x_10_3 = "eyJkZWJ1ZyI6I" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Linux_Eggshell_B_2147798581_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Eggshell.B"
        threat_id = "2147798581"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Eggshell"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "var" wide //weight: 2
        $x_10_2 = "777" wide //weight: 10
        $x_10_3 = "/tmp/espl.py" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

