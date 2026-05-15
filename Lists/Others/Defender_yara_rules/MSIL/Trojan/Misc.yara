rule Trojan_MSIL_Misc_SN_2147969408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Misc.SN!MTB"
        threat_id = "2147969408"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Misc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://1.192-168-0-1.top:5003/5003/192.168.0.71" wide //weight: 2
        $x_2_2 = "f85bbb88-ff44-467b-ad5c-5bb2eb4743ea" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

