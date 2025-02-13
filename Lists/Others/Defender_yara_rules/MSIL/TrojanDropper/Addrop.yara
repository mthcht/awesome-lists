rule TrojanDropper_MSIL_Addrop_B_2147726437_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Addrop.B!bit"
        threat_id = "2147726437"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Addrop"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/C netsh interface ip set dns name=\"" wide //weight: 1
        $x_1_2 = {11 5c 00 73 00 76 00 72 00 2e 00 63 00 72 00 74 00 00 37 2f 00 43 00 20 00 63 00 65 00 72 00 74 00 75 00 74 00 69 00 6c 00 20 00 2d 00 61 00 64 00 64 00 73 00 74 00 6f 00 72 00 65 00 20 00 52 00 6f 00 6f 00 74}  //weight: 1, accuracy: High
        $x_1_3 = "c:\\Users\\soc\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

