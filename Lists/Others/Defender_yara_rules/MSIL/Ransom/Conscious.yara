rule Ransom_MSIL_Conscious_MK_2147763827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Conscious.MK!MTB"
        threat_id = "2147763827"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Conscious"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\root\\cimv2" ascii //weight: 1
        $x_1_2 = "Consciousness Ransomware Text Message.txt" ascii //weight: 1
        $x_1_3 = "Your files has been encrypted successfully" ascii //weight: 1
        $x_1_4 = "Hacking activities had been run through out your computer/Laptop" ascii //weight: 1
        $x_1_5 = "transfer $400.00 to us with bitcoin" ascii //weight: 1
        $x_1_6 = ".Consciousness" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

