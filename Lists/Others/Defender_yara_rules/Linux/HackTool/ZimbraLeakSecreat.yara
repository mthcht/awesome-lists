rule HackTool_Linux_ZimbraLeakSecreat_A_2147977514_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/ZimbraLeakSecreat.A"
        threat_id = "2147977514"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "ZimbraLeakSecreat"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "zmlocalconfig" wide //weight: 10
        $x_10_2 = "_ldap_password" wide //weight: 10
        $x_10_3 = "ldap_postfix_password" wide //weight: 10
        $x_10_4 = "ldap_amavis_password" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

