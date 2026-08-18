rule Trojan_Win64_VorishkaStealer_MK_2147976336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VorishkaStealer.MK!MTB"
        threat_id = "2147976336"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VorishkaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "55"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "Vorishka.pdb" ascii //weight: 20
        $x_15_2 = "Start collect information to the folder:" ascii //weight: 15
        $x_10_3 = "=== System Information ===" ascii //weight: 10
        $x_5_4 = "\\DiscordTokens.txt" ascii //weight: 5
        $x_3_5 = "\\SystemInfo.txt" ascii //weight: 3
        $x_2_6 = "\\Cookies" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

