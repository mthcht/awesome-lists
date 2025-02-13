rule Backdoor_Linux_DemonBot_YA_2147741458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/DemonBot.YA!MTB"
        threat_id = "2147741458"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "DemonBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS" ascii //weight: 4
        $x_1_2 = "TSource Engine Query + /x54/x" ascii //weight: 1
        $x_1_3 = "31mV5.0" ascii //weight: 1
        $x_1_4 = "31mDemon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_DemonBot_Aa_2147763585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/DemonBot.Aa!MTB"
        threat_id = "2147763585"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "DemonBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Multihop attempted" ascii //weight: 1
        $x_1_2 = "billybobbot.com/crawler" ascii //weight: 1
        $x_2_3 = "YakuzaBotnet" ascii //weight: 2
        $x_1_4 = "UDPRAW" ascii //weight: 1
        $x_2_5 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T Hax" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_DemonBot_Ab_2147765930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/DemonBot.Ab!MTB"
        threat_id = "2147765930"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "DemonBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "STARTING TELNET SCANNER" ascii //weight: 1
        $x_1_2 = "STARTING 105 SCANNER" ascii //weight: 1
        $x_2_3 = {63 64 20 2f 74 6d 70 3b 62 75 73 79 62 6f 78 20 77 67 65 74 20 ?? ?? ?? ?? 3a 2f 2f [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 2f 69 6e 66 65 63 74 20 2d 4f 20 2d 20 3e 20 [0-16] 3b 20 62 75 73 79 62 6f 78 20 63 68 6d 6f 64 20 37 37 37 20 [0-16] 3b 20 73 68 20 2f 74 6d 70 2f}  //weight: 2, accuracy: Low
        $x_2_4 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T Hax" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

