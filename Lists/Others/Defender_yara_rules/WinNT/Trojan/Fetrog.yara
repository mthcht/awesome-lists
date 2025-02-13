rule Trojan_WinNT_Fetrog_A_2147666039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Fetrog.A"
        threat_id = "2147666039"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Fetrog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b f9 48 03 fa 48 33 c0 8a 01 41 f6 e0 49 03 c1 88 01 48 33 c0 48 ff c1 48 3b cf 75 eb}  //weight: 2, accuracy: High
        $x_2_2 = {80 39 eb 75 0c 48 0f be 41 01 48 8d 4c 08 02 eb 0e 80 39 e9 75 0e 48 63 41 01 48 8d 4c 08 05 b0 01 48 89 0a}  //weight: 2, accuracy: High
        $x_1_3 = "Net_U1ocike._2k" wide //weight: 1
        $x_1_4 = "f3t_0g.dat" wide //weight: 1
        $x_1_5 = "\\DosDevices\\rmpdk0g" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_WinNT_Fetrog_B_2147666040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Fetrog.B"
        threat_id = "2147666040"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Fetrog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "perfnw.pdb" ascii //weight: 1
        $x_2_2 = {0f b6 42 08 41 0f b7 c9 66 41 83 c1 02 42 30 04 01 0f b6 42 08 42 30 44 01 01 66 44 3b 4a 20 72 df}  //weight: 2, accuracy: High
        $x_2_3 = {66 41 89 43 04 44 0f b7 5c 24 ?? 44 0f b7 6c 24 ?? 66 41 81 f3 aa 55 66 41 81 f5 55 aa}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

