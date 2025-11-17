rule HackTool_Linux_PTHToolkitGenC_EE_2147766361_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/PTHToolkitGenC.EE"
        threat_id = "2147766361"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "PTHToolkitGenC"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "smb " wide //weight: 20
        $x_1_2 = "-u " wide //weight: 1
        $x_1_3 = "-id " wide //weight: 1
        $x_1_4 = "-x " wide //weight: 1
        $x_1_5 = "-k " wide //weight: 1
        $x_1_6 = "--kerberos" wide //weight: 1
        $x_1_7 = "-local-auth" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Linux_PTHToolkitGenC_FF_2147766362_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/PTHToolkitGenC.FF"
        threat_id = "2147766362"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "PTHToolkitGenC"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "winrm " wide //weight: 20
        $x_1_2 = "-u " wide //weight: 1
        $x_1_3 = "-id " wide //weight: 1
        $x_1_4 = "-x " wide //weight: 1
        $x_1_5 = "-k" wide //weight: 1
        $x_1_6 = "--kerberos" wide //weight: 1
        $x_1_7 = "-local-auth" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Linux_PTHToolkitGenC_GG_2147766363_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/PTHToolkitGenC.GG"
        threat_id = "2147766363"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "PTHToolkitGenC"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "ldap " wide //weight: 20
        $x_1_2 = "-u " wide //weight: 1
        $x_1_3 = "-id " wide //weight: 1
        $x_1_4 = "-x " wide //weight: 1
        $x_1_5 = "-k" wide //weight: 1
        $x_1_6 = "--kerberos" wide //weight: 1
        $x_1_7 = "-local-auth" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

