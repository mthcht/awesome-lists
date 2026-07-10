rule Trojan_MSIL_DBadur_SX_2147973286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DBadur.SX!MTB"
        threat_id = "2147973286"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DBadur"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "70"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "ECR-Confirmation-Code.txt" ascii //weight: 30
        $x_20_2 = "res1.bin" ascii //weight: 20
        $x_10_3 = "%s\" hosted_loader.p" ascii //weight: 10
        $x_5_4 = "download pyembed FAILED" ascii //weight: 5
        $x_5_5 = "decrypt pyembed FAILED" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

