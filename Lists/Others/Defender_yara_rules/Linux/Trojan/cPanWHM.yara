rule Trojan_Linux_cPanWHM_DA_2147974417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/cPanWHM.DA!MTB"
        threat_id = "2147974417"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "cPanWHM"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "+dirty" ascii //weight: 1
        $x_1_2 = "/root/toolkit/" ascii //weight: 1
        $x_1_3 = "main.checkGitHubToken" ascii //weight: 1
        $x_1_4 = "main.cpanelPersist" ascii //weight: 1
        $x_1_5 = "main.cpanelFullAccountExploit" ascii //weight: 1
        $x_1_6 = "main.verifyCPanelAuthBypass" ascii //weight: 1
        $x_1_7 = "main.verifyFortiOSWebSocketBypass" ascii //weight: 1
        $x_1_8 = "main.verifySpring4Shell" ascii //weight: 1
        $x_1_9 = "main.dumpGitHubRepo" ascii //weight: 1
        $x_1_10 = "main.s3OracleCheck" ascii //weight: 1
        $x_1_11 = "main.checkAWSWithCandidates" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

