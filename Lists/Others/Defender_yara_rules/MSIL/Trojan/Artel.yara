rule Trojan_MSIL_Artel_AB_2147903121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Artel.AB!MTB"
        threat_id = "2147903121"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Artel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hello From Main...I Don't Do Anything" wide //weight: 1
        $x_1_2 = "I shouldn't really execute" wide //weight: 1
        $x_1_3 = "\\AllTheThings.dll" ascii //weight: 1
        $x_1_4 = "dllguest.Bypass" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

