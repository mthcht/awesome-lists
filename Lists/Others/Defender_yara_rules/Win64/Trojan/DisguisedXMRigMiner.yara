rule Trojan_Win64_DisguisedXMRigMiner_SG_2147908721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DisguisedXMRigMiner.SG!MTB"
        threat_id = "2147908721"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DisguisedXMRigMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pool_wallet" ascii //weight: 1
        $x_1_2 = "nicehash" ascii //weight: 1
        $x_1_3 = "daemon-poll-interval" ascii //weight: 1
        $x_1_4 = "mining.authorize call failed" ascii //weight: 1
        $x_1_5 = "mining.extranonce.subscribe" ascii //weight: 1
        $x_1_6 = "va vyhrazena." wide //weight: 1
        $x_1_7 = "dxsetup.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

