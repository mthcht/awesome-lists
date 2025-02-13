rule Backdoor_Linux_Pupy_A_2147767500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Pupy.gen!A!!Pupy.gen!A"
        threat_id = "2147767500"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Pupy"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "Pupy: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pupylib.PupyCredentials" ascii //weight: 1
        $x_1_2 = "PupyTCPServer" ascii //weight: 1
        $x_1_3 = "BIND_PAYLOADS_PASSWORD" ascii //weight: 1
        $x_1_4 = "network/lib/launchers/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

