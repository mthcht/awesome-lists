rule Trojan_MSIL_Krolol_A_2147682620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Krolol.A"
        threat_id = "2147682620"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Krolol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "firewall set opmode disable" wide //weight: 1
        $x_1_2 = {6e 00 6f 00 74 00 65 00 70 00 61 00 64 00 2e 00 65 00 78 00 65 00 ?? ?? 6d 00 73 00 70 00 61 00 69 00 6e 00 74 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "set CDAudio door open" wide //weight: 1
        $x_1_4 = {53 00 68 00 65 00 6c 00 6c 00 5f 00 54 00 72 00 61 00 79 00 57 00 6e 00 64 00 00 01 00}  //weight: 1, accuracy: High
        $x_1_5 = "trololololololololololo.com" wide //weight: 1
        $x_1_6 = ".youporn.com" wide //weight: 1
        $x_1_7 = ".octopusgirl.com" wide //weight: 1
        $x_1_8 = ".loltrain.com" wide //weight: 1
        $x_1_9 = {5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 [0-64] 69 00 70 00 63 00 6f 00 6e 00 66 00 69 00 67 00 [0-10] 2f 00 72 00 65 00 6c 00 65 00 61 00 73 00 65 00}  //weight: 1, accuracy: Low
        $x_1_10 = "\\tmp.tmp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

