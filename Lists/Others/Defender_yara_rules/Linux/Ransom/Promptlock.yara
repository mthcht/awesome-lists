rule Ransom_Linux_Promptlock_A_2147951371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Promptlock.A!MTB"
        threat_id = "2147951371"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Promptlock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/home/discover/Ransomware3.0/go-llm-ransom/main.go" ascii //weight: 1
        $x_1_2 = "/home/discover/Ransomware3.0/go-llm-ransom/llm.go" ascii //weight: 1
        $x_1_3 = "main.runDecryptorGenTask" ascii //weight: 1
        $x_1_4 = "main.execLua.func1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

