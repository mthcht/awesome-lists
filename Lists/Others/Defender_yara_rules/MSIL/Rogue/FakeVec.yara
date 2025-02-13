rule Rogue_MSIL_FakeVec_157509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:MSIL/FakeVec"
        threat_id = "157509"
        type = "Rogue"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FakeVec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "<i>Vector</i><font color=\"#B02B2C\">Antivirus 1.0</font>" wide //weight: 1
        $x_1_2 = "Vector Antivirus 1.0" wide //weight: 1
        $x_1_3 = "Options for Virus" wide //weight: 1
        $x_1_4 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 ?? ?? ?? ?? 46 00 20 00 2f 00 49 00 4d 00 20 00 74 00 61 00 73 00 6b 00 6d 00 67 00 72 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

