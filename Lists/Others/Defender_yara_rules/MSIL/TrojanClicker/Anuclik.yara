rule TrojanClicker_MSIL_Anuclik_A_2147711662_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:MSIL/Anuclik.A"
        threat_id = "2147711662"
        type = "TrojanClicker"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Anuclik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/time1.txt" wide //weight: 1
        $x_1_2 = "/timeToClearCookie1.txt" wide //weight: 1
        $x_1_3 = "/googleAds.txt" wide //weight: 1
        $x_1_4 = "/siteBackLink1.txt" wide //weight: 1
        $x_1_5 = "InetCpl.cpl,ClearMyTracksByProcess 2" wide //weight: 1
        $x_1_6 = "userAgentFake" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

