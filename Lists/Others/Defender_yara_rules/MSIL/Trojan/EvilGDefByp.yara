rule Trojan_MSIL_EvilGDefByp_A_2147903126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/EvilGDefByp.A!MTB"
        threat_id = "2147903126"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "EvilGDefByp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Admin privelegies:" wide //weight: 1
        $x_1_2 = "Starting Elevating to SYSTEM" wide //weight: 1
        $x_10_3 = "Starting WD Disable" wide //weight: 10
        $x_10_4 = "MsMpEng" wide //weight: 10
        $x_1_5 = "Select * From Win32_Process Where ProcessID =" ascii //weight: 1
        $x_10_6 = "Disable WD\\ABC\\ABC\\obj\\Debug\\ABC.pdb" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

