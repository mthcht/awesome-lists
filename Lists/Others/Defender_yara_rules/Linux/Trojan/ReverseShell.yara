rule Trojan_Linux_ReverseShell_A_2147928900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/ReverseShell.A!MTB"
        threat_id = "2147928900"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "ReverseShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 54 24 20 48 8b 4a f8 48 89 8b 48 03 00 00 48 89 93 40 03 00 00 4c 3b b3 c0 00 00 00 75 07 48 8b 13 48 8b 62 38 48 83 ec 10 48 83 e4 f0 bf 01 00 00 00 48 8d 34 24 48 8b 05 bd b2 57 00 48 83 f8 00 74 3e ff d0 48 8b 04 24 48 8b 54 24 08 4c 89 e4 48 8b 4c 24 08 48 89 8b 40 03 00 00 48 8b 0c 24 48 89 8b 48 03 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 83 ec 18 48 89 6c 24 10 48 8d 6c 24 10 48 8b 7c 24 20 48 8b 74 24 28 48 8b 54 24 30 48 8b 05 ac d2 53 00 48 89 e3 48 83 e4 f0 ff d0 48 89 dc 89 44 24 38 48 8b 6c 24 10 48 83 c4 18 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_ReverseShell_B_2147929991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/ReverseShell.B!MTB"
        threat_id = "2147929991"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "ReverseShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.AsVirus" ascii //weight: 1
        $x_1_2 = "main.RemoveSelfExecutable" ascii //weight: 1
        $x_1_3 = "main.StartSocks5Server" ascii //weight: 1
        $x_1_4 = "main.CreateBackOff" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

