rule Trojan_MSIL_Hidtear_SA_2147779443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hidtear.SA!MTB"
        threat_id = "2147779443"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hidtear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Users\\aaa\\source\\repos\\crypt0r\\crypt0r\\obj\\Debug\\crypt0r.pdb" ascii //weight: 1
        $x_1_2 = "incorrect key" wide //weight: 1
        $x_1_3 = "DisableTaskMgr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

