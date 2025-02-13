rule Trojan_Win64_Merlin_A_2147925715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Merlin.A!dha"
        threat_id = "2147925715"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Merlin"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "merlin" ascii //weight: 1
        $x_1_2 = "parrot" ascii //weight: 1
        $x_1_3 = "Agent: %s" ascii //weight: 1
        $x_1_4 = "skew" ascii //weight: 1
        $x_1_5 = "KillDate" ascii //weight: 1
        $x_1_6 = "Platform" ascii //weight: 1
        $x_1_7 = "WaitTime" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

