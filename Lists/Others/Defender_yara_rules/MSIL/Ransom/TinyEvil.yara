rule Ransom_MSIL_TinyEvil_DA_2147772265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/TinyEvil.DA!MTB"
        threat_id = "2147772265"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TinyEvil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TinyEvil.exe" ascii //weight: 1
        $x_1_2 = "clrjit.dll" ascii //weight: 1
        $x_1_3 = "TinyEvil.Properties" ascii //weight: 1
        $x_1_4 = "RijndaelManaged" ascii //weight: 1
        $x_1_5 = "Encrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

