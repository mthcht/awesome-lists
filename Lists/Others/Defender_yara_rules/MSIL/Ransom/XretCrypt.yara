rule Ransom_MSIL_XretCrypt_PA_2147960381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/XretCrypt.PA!MTB"
        threat_id = "2147960381"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XretCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "SYSTEM HACKED BY XRET" wide //weight: 3
        $x_1_2 = "All information has been encrypted" wide //weight: 1
        $x_1_3 = "vssadmin Delete Shadows /All /Quiet" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

