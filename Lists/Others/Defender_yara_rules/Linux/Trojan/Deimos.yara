rule Trojan_Linux_Deimos_A_2147893578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Deimos.A!MTB"
        threat_id = "2147893578"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Deimos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/DeimosC2/DeimosC2/agents/resources/shellinject.ShellInject" ascii //weight: 1
        $x_1_2 = "shellcode_linux.go" ascii //weight: 1
        $x_1_3 = "/lib/privileges/isadmin_linux.go" ascii //weight: 1
        $x_1_4 = "/resources/agentfunctions.ShouldIDie" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

