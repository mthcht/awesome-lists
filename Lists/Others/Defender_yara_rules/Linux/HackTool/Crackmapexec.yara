rule HackTool_Linux_Crackmapexec_A_2147766360_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Crackmapexec.A"
        threat_id = "2147766360"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Crackmapexec"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "46"
        strings_accuracy = "High"
    strings:
        $x_40_1 = "crackmapexec" wide //weight: 40
        $x_5_2 = "smb " wide //weight: 5
        $x_5_3 = "winrm " wide //weight: 5
        $x_5_4 = "ldap " wide //weight: 5
        $x_5_5 = "mssql " wide //weight: 5
        $x_5_6 = "ssh " wide //weight: 5
        $x_1_7 = "-u " wide //weight: 1
        $x_1_8 = "-id " wide //weight: 1
        $x_1_9 = "-x " wide //weight: 1
        $x_1_10 = "-k" wide //weight: 1
        $x_1_11 = "-kerberos" wide //weight: 1
        $x_1_12 = "-local-auth" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_40_*) and 6 of ($x_1_*))) or
            ((1 of ($x_40_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_40_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

