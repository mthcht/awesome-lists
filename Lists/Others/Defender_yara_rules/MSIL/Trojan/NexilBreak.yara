rule Trojan_MSIL_NexilBreak_A_2147966410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NexilBreak.A!dha"
        threat_id = "2147966410"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NexilBreak"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Dynamite.Path" wide //weight: 1
        $x_1_2 = "Pick.FileManager" wide //weight: 1
        $x_1_3 = "pfd exception:" wide //weight: 1
        $x_1_4 = "osd exception:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NexilBreak_B_2147966412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NexilBreak.B!dha"
        threat_id = "2147966412"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NexilBreak"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Dominated.Route" wide //weight: 1
        $x_1_2 = "Moderator.Route" wide //weight: 1
        $x_1_3 = "err.log" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

