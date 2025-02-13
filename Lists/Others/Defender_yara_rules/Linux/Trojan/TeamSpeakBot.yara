rule Trojan_Linux_TeamSpeakBot_AA_2147842821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/TeamSpeakBot.AA"
        threat_id = "2147842821"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "TeamSpeakBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "chmod +x" ascii //weight: 2
        $x_2_2 = "B4ckdoor-owned-you-python-requests" ascii //weight: 2
        $x_2_3 = "User-Agent: Hello, World" ascii //weight: 2
        $x_2_4 = "POST /HNAP1/" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

