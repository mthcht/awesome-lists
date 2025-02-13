rule Ransom_MSIL_Ransim_MEL_2147925416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Ransim.MEL!MTB"
        threat_id = "2147925416"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ransim"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "spqqcify thqq -qqxtract" ascii //weight: 1
        $x_1_2 = "PCMNCi5TWU5PUFNJUw0KICAgUmVsZWFzZTogQmVhdXgNCiAgIFJhb" ascii //weight: 1
        $x_1_3 = "RubrikRanSim" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

