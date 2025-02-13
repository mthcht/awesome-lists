rule Backdoor_MSIL_PBot_2147709872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/PBot"
        threat_id = "2147709872"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "BotNet Browser is:" wide //weight: 2
        $x_2_2 = "[Join][PBotNet" wide //weight: 2
        $x_1_3 = "]Tracing|" wide //weight: 1
        $x_1_4 = "[Talk][" wide //weight: 1
        $x_1_5 = "]Off|" wide //weight: 1
        $x_1_6 = "[Join]" wide //weight: 1
        $x_1_7 = "[Left]" wide //weight: 1
        $x_1_8 = "[Usrs]" wide //weight: 1
        $x_1_9 = "udp_dos" wide //weight: 1
        $x_1_10 = "tcp_dos" wide //weight: 1
        $x_1_11 = "ip.txt" wide //weight: 1
        $x_2_12 = "Tsktra.exe" wide //weight: 2
        $x_2_13 = "Testo.txt" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

