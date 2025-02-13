rule Trojan_MSIL_NightingaleStealer_IKAA_2147905625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NightingaleStealer.IKAA!MTB"
        threat_id = "2147905625"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NightingaleStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 25 17 6f ?? 00 00 0a 25 18 6f ?? 00 00 0a 25 08 6f ?? 00 00 0a 25 09 6f ?? 00 00 0a 6f ?? 00 00 0a 07 16 07 8e 69 6f ?? 00 00 0a 0b}  //weight: 5, accuracy: Low
        $x_1_2 = "{7}[5][20]{20}[25][16][5]" ascii //weight: 1
        $x_1_3 = "{1}[19][19][5][13][2][12][25]" ascii //weight: 1
        $x_1_4 = "{12}[15][1][4]" ascii //weight: 1
        $x_1_5 = "{5}[14][20][18][25]{16}[15][9][14][20]" ascii //weight: 1
        $x_1_6 = "{9}[14][22][15][11][5]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

