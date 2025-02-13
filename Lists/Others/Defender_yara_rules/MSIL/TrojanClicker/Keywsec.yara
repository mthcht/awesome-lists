rule TrojanClicker_MSIL_Keywsec_A_2147665146_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:MSIL/Keywsec.A"
        threat_id = "2147665146"
        type = "TrojanClicker"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keywsec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 65 6c 70 65 72 00 4a 6f 62 00 48 74 74 70 52 65 71 75 65 73 74 00}  //weight: 2, accuracy: High
        $x_1_2 = "phantomjs.exe --web-security=no" wide //weight: 1
        $x_1_3 = "clicksOnSite" wide //weight: 1
        $x_1_4 = "timeOnSite" wide //weight: 1
        $x_1_5 = "\\..\\UserPrograms\\kwc\\" wide //weight: 1
        $x_1_6 = "jobs/set/sent/hash/" wide //weight: 1
        $x_1_7 = "/fetch/new/mac/" wide //weight: 1
        $x_1_8 = "campaignId" wide //weight: 1
        $x_1_9 = "phantomScript" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanClicker_MSIL_Keywsec_B_2147674446_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:MSIL/Keywsec.B"
        threat_id = "2147674446"
        type = "TrojanClicker"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keywsec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "clicksOnSite" wide //weight: 1
        $x_1_2 = "timeOnSite" wide //weight: 1
        $x_1_3 = "features/get/new/mac/" wide //weight: 1
        $x_1_4 = "jobs/set/image/index.php" wide //weight: 1
        $x_1_5 = "aHR0cDov" wide //weight: 1
        $x_1_6 = "campaignId" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

