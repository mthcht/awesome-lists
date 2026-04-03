rule Trojan_Win32_LokiC2Agent_A_2147966241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokiC2Agent.A"
        threat_id = "2147966241"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokiC2Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "execute-bof-node" ascii //weight: 2
        $x_2_2 = "execute-assembly-node" ascii //weight: 2
        $x_2_3 = "execute-scexec-node" ascii //weight: 2
        $x_1_4 = "bof-complete" ascii //weight: 1
        $x_1_5 = "assembly-complete" ascii //weight: 1
        $x_1_6 = "scexec-complete" ascii //weight: 1
        $x_2_7 = "COFFLoader.node" ascii //weight: 2
        $x_1_8 = "assembly.node" ascii //weight: 1
        $x_1_9 = "scexec.node" ascii //weight: 1
        $x_1_10 = "execute_assembly" ascii //weight: 1
        $x_1_11 = "runCOFF" ascii //weight: 1
        $x_1_12 = "run_array" ascii //weight: 1
        $x_1_13 = "socks-proxy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

