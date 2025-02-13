rule DoS_Linux_Elknot_E_2147684954_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Linux/Elknot.E"
        threat_id = "2147684954"
        type = "DoS"
        platform = "Linux: Linux platform"
        family = "Elknot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "13CThreadAttack" ascii //weight: 1
        $x_1_2 = ".ndfs30_api_log_utility_file_cut_and_move" ascii //weight: 1
        $x_1_3 = "17CThreadHostStatus" ascii //weight: 1
        $x_1_4 = "18CThreadTaskManager" ascii //weight: 1
        $x_1_5 = "12CThreadTimer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

