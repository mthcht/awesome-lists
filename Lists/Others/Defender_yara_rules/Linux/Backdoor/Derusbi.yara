rule Backdoor_Linux_Derusbi_A_2147783284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Derusbi.A!MTB"
        threat_id = "2147783284"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Derusbi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "81bc3f05e513dd0f037cb0d81af9edbd" ascii //weight: 1
        $x_1_2 = "/dev/shm/.profile_log" ascii //weight: 1
        $x_1_3 = "/dev/shm/.shmfs.lock" ascii //weight: 1
        $x_1_4 = "\\u@\\h:\\w \\$" ascii //weight: 1
        $x_1_5 = "/tmp/.secure" ascii //weight: 1
        $x_1_6 = {89 c1 89 f7 83 c0 01 83 e1 03 c1 e1 03 d3 ef 40 30 3b 48 83 c3 01 39 d0 72 e6 e9 35 ff ff ff}  //weight: 1, accuracy: High
        $x_1_7 = {8b 85 e4 fd ff ff 89 f1 83 c6 01 83 e1 03 c1 e1 03 d3 e8 30 02 83 c2 01 39 f7 77 e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

