rule HackTool_Linux_CredShadow_C_2147951155_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/CredShadow.C"
        threat_id = "2147951155"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "CredShadow"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "awk // /etc/shadow" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

