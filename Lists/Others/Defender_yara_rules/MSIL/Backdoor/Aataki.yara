rule Backdoor_MSIL_Aataki_A_2147695310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Aataki.A"
        threat_id = "2147695310"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Aataki"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CONNECTED|1.1|" wide //weight: 1
        $x_1_2 = "STATUS|SSYN Attacking" wide //weight: 1
        $x_1_3 = "STATUS|TCP DDos on" wide //weight: 1
        $x_1_4 = "UDP Flooding" wide //weight: 1
        $x_1_5 = "autorun.inf" wide //weight: 1
        $x_1_6 = "StartSuperSyn" ascii //weight: 1
        $x_1_7 = "_floodingJob" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

