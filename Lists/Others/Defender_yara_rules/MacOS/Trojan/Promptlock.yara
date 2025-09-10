rule Trojan_MacOS_Promptlock_A_2147951898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Promptlock.A"
        threat_id = "2147951898"
        type = "Trojan"
        platform = "MacOS: "
        family = "Promptlock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Generate clean, working Lua code" ascii //weight: 1
        $x_1_2 = "you are a Lua code validator" ascii //weight: 1
        $x_1_3 = "/ollama/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

