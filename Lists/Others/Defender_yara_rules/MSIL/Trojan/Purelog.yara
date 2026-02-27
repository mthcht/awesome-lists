rule Trojan_MSIL_Purelog_MX_2147963811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Purelog.MX!MTB"
        threat_id = "2147963811"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Purelog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Qibanonana.pdb" ascii //weight: 1
        $x_1_2 = "S2um4DXYAxufWRrhFw.glbAguPWPo0Hc6QUgJ" ascii //weight: 1
        $x_1_3 = "is tampered" ascii //weight: 1
        $x_1_4 = "Debugger Detected" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

