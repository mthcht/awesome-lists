rule HackTool_Linux_ZimbraSuspLDAP_A_2147977515_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/ZimbraSuspLDAP.A"
        threat_id = "2147977515"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "ZimbraSuspLDAP"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "ldapsearch" wide //weight: 50
        $x_50_2 = "cn=admins,cn=" wide //weight: 50
        $x_1_3 = "zimbraAuthTokenKey" wide //weight: 1
        $x_1_4 = "zimbraPreAuthKey" wide //weight: 1
        $x_1_5 = "zimbraAuthTokens" wide //weight: 1
        $x_1_6 = "zimbraTwoFactorAuthSecret" wide //weight: 1
        $x_1_7 = "zimbraAppSpecificPassword" wide //weight: 1
        $x_1_8 = "zimbraGalLdapBindPassword" wide //weight: 1
        $x_1_9 = "zimbraDataSourcePassword" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_50_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

