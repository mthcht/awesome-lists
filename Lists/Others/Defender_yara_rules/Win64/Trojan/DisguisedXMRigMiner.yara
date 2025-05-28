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

rule Trojan_Win64_DisguisedXMRigMiner_MX_2147942375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DisguisedXMRigMiner.MX!MTB"
        threat_id = "2147942375"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DisguisedXMRigMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {85 c0 74 1f 0f bf 44 24 40 0f bf 4c 24 50 89 05 0e bf 21 00 0f bf 44 24 4c 2b c8 ff c1 89 0d f3 be 21 00 48 8b 4c 24 58 48 33 cc}  //weight: 1, accuracy: High
        $x_1_2 = "Golang-Updater" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

