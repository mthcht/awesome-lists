rule Trojan_Linux_Promptlock_A_2147951897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Promptlock.A"
        threat_id = "2147951897"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Promptlock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Generate clean, working Lua cod" ascii //weight: 1
        $x_1_2 = "you are a Lua code validator" ascii //weight: 1
        $x_1_3 = "/ollama/" ascii //weight: 1
        $x_1_4 = "Summarize the information which was found for each file in the context of a cybersecurity expert," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

