rule Trojan_Win32_Cassandra_EI_2147957063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cassandra.EI!MTB"
        threat_id = "2147957063"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cassandra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OGame TTT.dll" ascii //weight: 1
        $x_1_2 = "GameMinds AI Lab" ascii //weight: 1
        $x_1_3 = "Advanced tic-tac-toe with neural network AI opponent" ascii //weight: 1
        $x_1_4 = "UltimateTTT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

