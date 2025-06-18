rule HackTool_MacOS_MythicAthena_I_2147943928_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/MythicAthena.I"
        threat_id = "2147943928"
        type = "HackTool"
        platform = "MacOS: "
        family = "MythicAthena"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Athena.dll" ascii //weight: 1
        $x_1_2 = "@_gss_acquire_cred_with_password" ascii //weight: 1
        $x_1_3 = "hackishClassName" ascii //weight: 1
        $x_1_4 = "@_kill" ascii //weight: 1
        $x_1_5 = "@_gethostname" ascii //weight: 1
        $x_1_6 = "@_geteuid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

