rule Trojan_MacOS_MemTenSteal_DA_2147978769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/MemTenSteal.DA!MTB"
        threat_id = "2147978769"
        type = "Trojan"
        platform = "MacOS: "
        family = "MemTenSteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "supplychain.local/campaign/internal/agent." ascii //weight: 1
        $x_1_2 = ".credentialsFromFile" ascii //weight: 1
        $x_1_3 = ".credentialPaths" ascii //weight: 1
        $x_1_4 = "User-Agent: %s" ascii //weight: 1
        $x_1_5 = "chacha20poly1305" ascii //weight: 1
        $x_1_6 = "awaiting_authorization" ascii //weight: 1
        $x_1_7 = "all_credential_env" ascii //weight: 1
        $x_1_8 = "exec.Cmd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

