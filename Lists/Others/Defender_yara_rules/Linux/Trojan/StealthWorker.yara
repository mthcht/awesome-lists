rule Trojan_Linux_StealthWorker_A_2147832679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/StealthWorker.A!MTB"
        threat_id = "2147832679"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "StealthWorker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WorkerSSH_brut.check_honeypot" ascii //weight: 1
        $x_1_2 = "WorkerSSH_brut.SaveGood" ascii //weight: 1
        $x_1_3 = "WorkerHtpasswd_check" ascii //weight: 1
        $x_1_4 = "WorkerWHM_brut" ascii //weight: 1
        $x_1_5 = "WorkerFTP_check" ascii //weight: 1
        $x_1_6 = "WorkerHtpasswd_brut" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

