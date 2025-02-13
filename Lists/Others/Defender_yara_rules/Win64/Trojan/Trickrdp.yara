rule Trojan_Win64_Trickrdp_A_2147766725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trickrdp.A!MTB"
        threat_id = "2147766725"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trickrdp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rdpscan.dll" ascii //weight: 1
        $x_1_2 = "BotID" ascii //weight: 1
        $x_1_3 = "trybrute" ascii //weight: 1
        $x_1_4 = "rdp/names" ascii //weight: 1
        $x_1_5 = "rdp/dict" ascii //weight: 1
        $x_1_6 = "rdp/over" ascii //weight: 1
        $x_1_7 = "rdp/freq" ascii //weight: 1
        $x_1_8 = "rdp/domains" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Trickrdp_B_2147766726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Trickrdp.B!MTB"
        threat_id = "2147766726"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Trickrdp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "rdpscan.dll" ascii //weight: 1
        $x_1_2 = "F:\\rdpscan\\Bin\\Release_logged\\x64\\rdpscan.pdb" ascii //weight: 1
        $x_1_3 = {46 72 65 65 42 75 66 66 65 72 [0-4] 52 65 6c 65 61 73 65 [0-4] 53 74 61 72 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

