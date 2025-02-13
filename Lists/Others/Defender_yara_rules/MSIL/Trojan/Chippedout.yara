rule Trojan_MSIL_Chippedout_A_2147723446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Chippedout.A!dha"
        threat_id = "2147723446"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Chippedout"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Reverse shell exceeded lifetime. Shutting down." wide //weight: 1
        $x_1_2 = "Chipmunk.resources.Communication.dll" wide //weight: 1
        $x_1_3 = "DPG Attack Team" wide //weight: 1
        $x_1_4 = "ERROR Pipeline Stopped:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

