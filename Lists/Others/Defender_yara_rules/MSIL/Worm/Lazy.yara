rule Worm_MSIL_Lazy_SN_2147975032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Lazy.SN!MTB"
        threat_id = "2147975032"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {02 7b 10 00 00 04 73 65 00 00 0a 0b 02 72 b7 02 00 70 6f 2f 00 00 06 00 72 ed 02 00 70 0c 06 02 08 6f 31 00 00 06 07 6f 66 00 00 0a 6f 67 00 00 0a 00 02 6f 2a 00 00 06 0d 09 2c 0c}  //weight: 5, accuracy: High
        $x_1_2 = "C:\\systemcli" wide //weight: 1
        $x_2_3 = "systemc\\obj\\x86\\Debug\\systemc.pdb" ascii //weight: 2
        $x_2_4 = "63c289a7-af28-4667-b616-9c284dd32386" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

