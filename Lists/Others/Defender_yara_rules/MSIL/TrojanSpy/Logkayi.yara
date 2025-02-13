rule TrojanSpy_MSIL_Logkayi_A_2147706586_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Logkayi.A"
        threat_id = "2147706586"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Logkayi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "J4ZLBLye1XUINQaZX8jwdA==" wide //weight: 1
        $x_1_2 = {2e 00 53 00 43 00 52 00 ?? ?? 23 00 67 00 65 00 74 00 65 00 64 00 65 00 72 00 23 00}  //weight: 1, accuracy: Low
        $x_1_3 = "gfxScreenshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

