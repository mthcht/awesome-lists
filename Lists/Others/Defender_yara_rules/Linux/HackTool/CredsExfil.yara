rule HackTool_Linux_CredsExfil_A_2147916735_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/CredsExfil.A"
        threat_id = "2147916735"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "CredsExfil"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "curl -F" wide //weight: 1
        $x_1_2 = "curl --form" wide //weight: 1
        $x_10_3 = "/.aws/credentials" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Linux_CredsExfil_B_2147916736_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/CredsExfil.B"
        threat_id = "2147916736"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "CredsExfil"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "curl -F" wide //weight: 1
        $x_1_2 = "curl --form" wide //weight: 1
        $x_10_3 = "/root/.ssh/id" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Linux_CredsExfil_C_2147916737_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/CredsExfil.C"
        threat_id = "2147916737"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "CredsExfil"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "curl -F" wide //weight: 1
        $x_1_2 = "curl --form" wide //weight: 1
        $x_10_3 = "/etc/shadow" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Linux_CredsExfil_E_2147916738_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/CredsExfil.E"
        threat_id = "2147916738"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "CredsExfil"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "curl -F" wide //weight: 1
        $x_1_2 = "curl --form" wide //weight: 1
        $x_10_3 = ".bash_history" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Linux_CredsExfil_D_2147916978_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/CredsExfil.D"
        threat_id = "2147916978"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "CredsExfil"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "curl -F" wide //weight: 1
        $x_1_2 = "curl --form" wide //weight: 1
        $x_10_3 = "/etc/passwd" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

