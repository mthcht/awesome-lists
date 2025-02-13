rule Ransom_MacOS_Turtle_A_2147901529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MacOS/Turtle.A!MTB"
        threat_id = "2147901529"
        type = "Ransom"
        platform = "MacOS: "
        family = "Turtle"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.en0cr0yp0tFile" ascii //weight: 1
        $x_1_2 = "/VirTest/TurmiRansom/main.go" ascii //weight: 1
        $x_1_3 = "path/filepath.Walk" ascii //weight: 1
        $x_1_4 = ".TURTLERANSv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

