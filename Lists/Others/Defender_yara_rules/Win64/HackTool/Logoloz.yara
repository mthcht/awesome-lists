rule HackTool_Win64_Logoloz_DZ_2147926576_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Logoloz.DZ!MTB"
        threat_id = "2147926576"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Logoloz"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Go build ID:" ascii //weight: 1
        $x_2_2 = "github.com/nicocha30/ligolo-ng" ascii //weight: 2
        $x_2_3 = "DzDIF6Sd7GD2sX0kDFpHAsJMY4L+OfTvtuaQsOYXxzk" ascii //weight: 2
        $x_1_4 = "client finished" ascii //weight: 1
        $x_2_5 = "cQriyiUvjTwOHg8QZaPihLWeRAAVoCpE00IUPn0Bjt8" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

