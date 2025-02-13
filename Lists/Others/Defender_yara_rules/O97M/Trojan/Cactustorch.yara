rule Trojan_O97M_Cactustorch_2147728279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Cactustorch"
        threat_id = "2147728279"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Cactustorch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "& \"21546869732070726F6772616D2063616E6E6F742062652072756E20696E20444F53206D6F64652E0D0D0A24000000000000\"" ascii //weight: 1
        $x_1_2 = "& \"617373656D626C79067461726765741274617267657454797065417373656D626C790E746172676574547970654E616D650A\"" ascii //weight: 1
        $x_1_3 = "& \"383906140000000774617267657430090600000006160000001A53797374656D2E5265666C656374696F6E2E417373656D62\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Cactustorch_A_2147728281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Cactustorch.A"
        threat_id = "2147728281"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Cactustorch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "& \"NWM1NjE5MzRlMDg5BhQAAAAHdGFyZ2V0MAkGAAAABhYAAAAaU3lzdGVtLlJlZmxlY3Rpb24uQXNz\"" ascii //weight: 1
        $x_1_2 = "& \"YW0gY2Fubm90IGJlIHJ1biBpbiBET1MgbW9kZS4NDQokAAAAAAAAAFBFAABMAQMALPkZWQAAAAAA\"" ascii //weight: 1
        $x_1_3 = "& \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAADh+6DgC0Cc0huAFMzSFUaGlzIHByb2dy\"" ascii //weight: 1
        $x_1_4 = "& \"AwAAAAhEZWxlZ2F0ZQd0YXJnZXQwB21ldGhvZDADAwMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXph\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

