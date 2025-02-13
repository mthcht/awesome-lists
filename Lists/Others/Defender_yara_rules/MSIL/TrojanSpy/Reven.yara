rule TrojanSpy_MSIL_Reven_A_2147724561_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Reven.A!bit"
        threat_id = "2147724561"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Reven"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "usbSpreader" ascii //weight: 1
        $x_1_2 = {54 65 61 6d 52 65 76 65 6e 67 65 2d [0-8] 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

