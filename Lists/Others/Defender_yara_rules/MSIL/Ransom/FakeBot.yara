rule Ransom_MSIL_FakeBot_MK_2147788444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FakeBot.MK!MTB"
        threat_id = "2147788444"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FakeBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YOUR FILES ARE ENCRYPTED" ascii //weight: 1
        $x_1_2 = "important data has been copied to our vault" ascii //weight: 1
        $x_1_3 = "SENDMYiDbot" ascii //weight: 1
        $x_1_4 = "cost increases with time, don't waste your time" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

