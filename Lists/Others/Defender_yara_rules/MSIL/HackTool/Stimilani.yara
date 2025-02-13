rule HackTool_MSIL_Stimilani_A_2147696479_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Stimilani.A"
        threat_id = "2147696479"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stimilani"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tradeoffer/new/send" ascii //weight: 1
        $x_1_2 = "steamcommunity.com" ascii //weight: 1
        $x_1_3 = "steamLogin" ascii //weight: 1
        $x_1_4 = "rgInventory" ascii //weight: 1
        $x_1_5 = "json_tradeoffer" ascii //weight: 1
        $x_1_6 = "STATUS IS UNKNOWN - THIS SHOULD NEVER HAPPEN!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

