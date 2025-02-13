rule Trojan_MSIL_Splinter_A_2147773977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Splinter.A!dha"
        threat_id = "2147773977"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Splinter"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "4969745b-8f72-4c3c-91ef-10405740b9c3" ascii //weight: 3
        $x_2_2 = ".src.Network.Packets.Receive" ascii //weight: 2
        $x_1_3 = "R_HeartbeatMessage" ascii //weight: 1
        $x_1_4 = "FileMgr get Folders" wide //weight: 1
        $x_1_5 = "6D007300770069006E0068006F00730074007300760063002E006E0065007400" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

