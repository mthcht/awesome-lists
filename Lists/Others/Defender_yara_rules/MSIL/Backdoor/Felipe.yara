rule Backdoor_MSIL_Felipe_YA_2147740732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Felipe.YA!MTB"
        threat_id = "2147740732"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Felipe"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "- infect.txt" wide //weight: 1
        $x_1_2 = "&&tipo=procfalse&&subdir=" wide //weight: 1
        $x_1_3 = "&&arq=proctrue.txt&&usr=" wide //weight: 1
        $x_1_4 = "&&arq=atualiza.txt&&usr=" wide //weight: 1
        $x_1_5 = "w=lambeu explorer&&arq=" wide //weight: 1
        $x_1_6 = "uploads\\proctrue.txt" wide //weight: 1
        $x_1_7 = "uploads\\procfalok.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

