rule TrojanSpy_MSIL_Dercky_A_2147725792_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Dercky.A!bit"
        threat_id = "2147725792"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dercky"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "0x00010|||||||||67521824" wide //weight: 2
        $x_2_2 = "58.218.200.13" wide //weight: 2
        $x_1_3 = "http://dec.ip3366.net/api/?key=20171119174239256&getnum=99999&proxytype=0" wide //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

