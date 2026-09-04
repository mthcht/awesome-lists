rule HackTool_Linux_ZimbraPLE_A_2147977516_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/ZimbraPLE.A"
        threat_id = "2147977516"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "ZimbraPLE"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/bin/ln" wide //weight: 10
        $x_10_2 = "/etc/pam.d/" wide //weight: 10
        $x_10_3 = "zmmailboxd" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

