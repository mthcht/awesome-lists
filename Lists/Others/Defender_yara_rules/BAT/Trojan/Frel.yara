rule Trojan_BAT_Frel_A_2147650171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:BAT/Frel.A"
        threat_id = "2147650171"
        type = "Trojan"
        platform = "BAT: Basic scripts"
        family = "Frel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Title Avast! Virus Alert" ascii //weight: 1
        $x_1_2 = "echo Un virus a ete detecte sur votre ordinateur" ascii //weight: 1
        $x_1_3 = "if %input%==o goto o" ascii //weight: 1
        $x_1_4 = "echo Vous vous ete fait prendre par se faux virus innofensif " ascii //weight: 1
        $x_1_5 = "ping localhost -n 4 > nul" ascii //weight: 1
        $x_1_6 = "echo Code PIN correct" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

