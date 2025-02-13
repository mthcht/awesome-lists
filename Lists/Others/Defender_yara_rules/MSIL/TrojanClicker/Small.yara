rule TrojanClicker_MSIL_Small_ARAX_2147911645_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:MSIL/Small.ARAX!MTB"
        threat_id = "2147911645"
        type = "TrojanClicker"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\deadeye2.pdb" ascii //weight: 2
        $x_5_2 = "/view_video.php?viewkey=" wide //weight: 5
        $x_5_3 = "--mute-audio" wide //weight: 5
        $x_2_4 = "\\Google\\Chrome\\User Data" wide //weight: 2
        $x_2_5 = "window.scrollBy(0, window.innerHeight * 2)" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

