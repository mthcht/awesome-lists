rule Trojan_MSIL_Punminer_A_2147697173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Punminer.A"
        threat_id = "2147697173"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Punminer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Miner" ascii //weight: 1
        $x_1_2 = ".vbs" wide //weight: 1
        $x_1_3 = "proxy" ascii //weight: 1
        $x_1_4 = {68 69 64 64 65 6e [0-16] 52 75 6e}  //weight: 1, accuracy: Low
        $x_1_5 = {52 75 6e 4f 6e 63 65 [0-16] 44 65 6c ?? ?? ?? 46 69 6c 65}  //weight: 1, accuracy: Low
        $x_1_6 = {24 00 2d 00 75 00 72 00 [0-16] 2d 00 24 00 75 00 73 00 [0-16] 61 00 73 00 73 00}  //weight: 1, accuracy: Low
        $x_1_7 = "me.yw/C" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

