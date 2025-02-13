rule Trojan_MSIL_Gomspol_A_2147690188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Gomspol.A"
        threat_id = "2147690188"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gomspol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "1GcDaNXwpvd7kuPCicWUEXjKbBkp61WVnh -p d=0.01" wide //weight: 1
        $x_1_2 = "md64/taskstart.exe" wide //weight: 1
        $x_1_3 = "gamecomp.net" wide //weight: 1
        $x_1_4 = "useast.wafflepool.com:3331 -u" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

