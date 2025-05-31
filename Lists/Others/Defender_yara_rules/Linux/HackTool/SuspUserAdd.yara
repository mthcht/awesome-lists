rule HackTool_Linux_SuspUserAdd_E_2147942583_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspUserAdd.E"
        threat_id = "2147942583"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspUserAdd"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "useradd" wide //weight: 10
        $x_10_2 = "aiuser" wide //weight: 10
        $x_10_3 = "-K MAIL_DIR=/dev/null" wide //weight: 10
        $x_10_4 = "-K MAIL_FILE=/dev/null" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

