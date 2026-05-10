rule HackTool_Linux_GsnetcatMem_A_2147968938_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/GsnetcatMem.A!!GsnetcatMem.A"
        threat_id = "2147968938"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "GsnetcatMem"
        severity = "High"
        info = "GsnetcatMem: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "GSRN connection established [via TOR to" ascii //weight: 3
        $x_2_2 = "_GSOCKET_WANT_AUTHCOOKIE" ascii //weight: 2
        $x_2_3 = "srp_generate_client_master_secret" ascii //weight: 2
        $x_1_4 = "_GSOCKET_SERVER_CHECK_SEC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

