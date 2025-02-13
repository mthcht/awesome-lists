rule HackTool_Linux_Keimpx_A_2147765167_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Keimpx.A"
        threat_id = "2147765167"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Keimpx"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "python" wide //weight: 1
        $x_20_2 = "keimpx" wide //weight: 20
        $x_1_3 = "-u " wide //weight: 1
        $x_1_4 = "-p " wide //weight: 1
        $x_1_5 = "-t " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Linux_Keimpx_B_2147765168_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Keimpx.B"
        threat_id = "2147765168"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Keimpx"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "python" wide //weight: 1
        $x_20_2 = "keimpx" wide //weight: 20
        $x_1_3 = "--lm=" wide //weight: 1
        $x_1_4 = "--nt=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Linux_Keimpx_BB_2147766356_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Keimpx.BB"
        threat_id = "2147766356"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Keimpx"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "python" wide //weight: 1
        $x_20_2 = "keimpx" wide //weight: 20
        $x_1_3 = "-u " wide //weight: 1
        $x_1_4 = "-p " wide //weight: 1
        $x_1_5 = "-l " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Linux_Keimpx_CC_2147766358_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Keimpx.CC"
        threat_id = "2147766358"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Keimpx"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "python" wide //weight: 1
        $x_20_2 = "keimpx" wide //weight: 20
        $x_1_3 = "-c " wide //weight: 1
        $x_1_4 = "-l " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Linux_Keimpx_DD_2147766359_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Keimpx.DD"
        threat_id = "2147766359"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Keimpx"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "python" wide //weight: 1
        $x_20_2 = "keimpx" wide //weight: 20
        $x_1_3 = "-c " wide //weight: 1
        $x_1_4 = "-t " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Linux_Keimpx_A_2147768608_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Keimpx.gen!A!!Keimpx.gen!A"
        threat_id = "2147768608"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Keimpx"
        severity = "High"
        info = "gen: malware that is detected using a generic signature"
        info = "Keimpx: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Launching interactive SMB shell" ascii //weight: 1
        $x_1_2 = "keimpx" ascii //weight: 1
        $x_1_3 = "bindshell [port]" ascii //weight: 1
        $x_1_4 = "svcshell [mode]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

