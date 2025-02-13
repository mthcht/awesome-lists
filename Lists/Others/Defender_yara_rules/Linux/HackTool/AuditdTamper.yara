rule HackTool_Linux_AuditdTamper_A_2147775336_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/AuditdTamper.A"
        threat_id = "2147775336"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "AuditdTamper"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "auditctl -e0" wide //weight: 10
        $x_10_2 = "auditctl -e 0" wide //weight: 10
        $x_10_3 = "systemctl disable auditd" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

