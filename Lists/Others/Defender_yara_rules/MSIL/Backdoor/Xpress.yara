rule Backdoor_MSIL_Xpress_B_2147655123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Xpress.B"
        threat_id = "2147655123"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xpress"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XPress Bot\\XPress2" ascii //weight: 1
        $x_1_2 = "udp.flood/exec/kill" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

