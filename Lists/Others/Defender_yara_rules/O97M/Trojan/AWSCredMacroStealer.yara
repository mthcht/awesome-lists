rule Trojan_O97M_AWSCredMacroStealer_A_2147965283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/AWSCredMacroStealer.A"
        threat_id = "2147965283"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "AWSCredMacroStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "https://webhook.site/6d61998b-a8fb-4e57-874d-d2e9a38bda7" ascii //weight: 5
        $x_5_2 = "http://169.254.169.254/latest/meta-data/iam/security-credentials" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

