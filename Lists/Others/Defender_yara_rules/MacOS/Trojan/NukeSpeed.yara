rule Trojan_MacOS_NukeSpeed_AMTB_2147970170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/NukeSpeed!AMTB"
        threat_id = "2147970170"
        type = "Trojan"
        platform = "MacOS: "
        family = "NukeSpeed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Qo_AZGA1_GA9_GA9_GA9_G" ascii //weight: 1
        $x_1_2 = "GA9_GA24_yAIGGG_" ascii //weight: 1
        $x_1_3 = "Qo_A0_GA3_GA11_GA11_GA11_G" ascii //weight: 1
        $x_1_4 = "GA11_GA26_yAKGGG_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

