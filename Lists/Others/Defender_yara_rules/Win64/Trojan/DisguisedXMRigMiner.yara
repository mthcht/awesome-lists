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
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {85 c0 74 1f 0f bf 44 24 40 0f bf 4c 24 50 89 05 0e bf 21 00 0f bf 44 24 4c 2b c8 ff c1 89 0d f3 be 21 00 48 8b 4c 24 58 48 33 cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DisguisedXMRigMiner_MX_2147942375_1
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
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 14 4c 8b d1 49 c1 ea 0c 4d 03 d3 41 80 3a 00 75 04 41 c6 02 ff}  //weight: 1, accuracy: High
        $x_5_2 = "MicrosoftEdgeUpdater.dll" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DisguisedXMRigMiner_NG_2147971673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DisguisedXMRigMiner.NG!MTB"
        threat_id = "2147971673"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DisguisedXMRigMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {49 8d 40 01 48 89 ce 4c 89 c3 48 ba 2d 7f 95 4c 2d f4 51 58 4c 8d 69 20 48 8d a9 e0 c3 00 00 48 0f af c2 48 ba fc a1 f5 59 8a 97 0a 81 48 31 c2 48 89 44 24 20 48 89 54 24 28 48 ba 46 d8 c2 38 df 99 70 a7 48 31 c2 48 89 54 24 30}  //weight: 2, accuracy: High
        $x_2_2 = {48 8b 03 48 31 44 24 20 48 8b 43 08 48 31 44 24 28 48 8b 43 10 48 31 44 24 30 48 8b 43 18 48 31 44 24 38 48 8b 43 20 48 31 44 24 40 48 8b 43 28 48 31 44 24 48 48 8b 43 30 48 31 44 24 50 48 8b 43 38 48 31 44 24 58 49 63 45 9c 48 8b 5c c4 20 4c 39 ed}  //weight: 2, accuracy: High
        $x_1_3 = "xmrig" ascii //weight: 1
        $x_1_4 = "wallet_address" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

