rule HackTool_MSIL_HotBrute_A_2147658928_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/HotBrute.A"
        threat_id = "2147658928"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HotBrute"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nBrute_Force.My.Resources" ascii //weight: 1
        $x_1_2 = "nBrute Force v" wide //weight: 1
        $x_1_3 = "Coded By: njq8 Email: njq8@ymail.com" wide //weight: 1
        $x_1_4 = "pop3.live.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

