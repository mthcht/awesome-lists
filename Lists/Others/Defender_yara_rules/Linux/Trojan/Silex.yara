rule Trojan_Linux_Silex_A_2147793493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Silex.A!MTB"
        threat_id = "2147793493"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Silex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://185.162.235.56/bricker.sh; sh bricker.sh" ascii //weight: 2
        $x_1_2 = "illed bot process" ascii //weight: 1
        $x_1_3 = "[silexbot] i am only here to prevent skids to flex their skidded botnet" ascii //weight: 1
        $x_1_4 = "people selling spots on botnets" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

