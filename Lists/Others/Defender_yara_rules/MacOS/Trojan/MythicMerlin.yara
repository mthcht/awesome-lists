rule Trojan_MacOS_MythicMerlin_A_2147849662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/MythicMerlin.A"
        threat_id = "2147849662"
        type = "Trojan"
        platform = "MacOS: "
        family = "MythicMerlin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Ne0nd0g/merlin-agent/clients/mythic" ascii //weight: 2
        $x_1_2 = "Mythic/agent/main.go" ascii //weight: 1
        $x_1_3 = "mythic.PostResponse" ascii //weight: 1
        $x_1_4 = "mythic.Task" ascii //weight: 1
        $x_1_5 = "mythic.Client" ascii //weight: 1
        $x_1_6 = "mythic.Config" ascii //weight: 1
        $x_1_7 = "mythic.CheckIn" ascii //weight: 1
        $x_1_8 = "mythic.RSARequest" ascii //weight: 1
        $x_1_9 = "mythic.RSAResponse" ascii //weight: 1
        $x_1_10 = "mythic.FileDownload" ascii //weight: 1
        $x_1_11 = "jobs.Shellcode" ascii //weight: 1
        $x_1_12 = "jobs.FileTransfer" ascii //weight: 1
        $x_1_13 = "MerlinClient" ascii //weight: 1
        $x_1_14 = "MythicID" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

