rule Trojan_MSIL_Swotter_FAC_2147781335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Swotter.FAC!MTB"
        threat_id = "2147781335"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Swotter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {06 17 d6 0a 09 17 d6 0d 09 20 ff c9 00 00 31 c8}  //weight: 10, accuracy: High
        $x_5_2 = "IDM.IUelpmiS" ascii //weight: 5
        $x_5_3 = "RMSplash" ascii //weight: 5
        $x_4_4 = "\\RosterLoad.txt" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

