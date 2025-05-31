rule HackTool_Linux_SuspPrivilegeEscalation_A_2147942585_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspPrivilegeEscalation.A"
        threat_id = "2147942585"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspPrivilegeEscalation"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "chmod g+s /tmp/aiq-" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

