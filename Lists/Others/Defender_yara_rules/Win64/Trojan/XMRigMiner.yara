rule Trojan_Win64_XMRigMiner_GS_2147755627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XMRigMiner.GS!MTB"
        threat_id = "2147755627"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XMRigMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "donate-over-proxy" ascii //weight: 2
        $x_2_2 = "pools" ascii //weight: 2
        $x_2_3 = "rig-id" ascii //weight: 2
        $x_2_4 = "nop=${NUMBER_OF_PROCESSORS}" ascii //weight: 2
        $x_1_5 = "f2pool.com" ascii //weight: 1
        $x_1_6 = "skypool.org" ascii //weight: 1
        $x_1_7 = "hashvault.promo" ascii //weight: 1
        $x_1_8 = {ff 13 48 83 eb 08 48 39 f3 75 f5 48 8d 0d ?? ?? ?? ?? 48 83 c4 28 5b 5e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

