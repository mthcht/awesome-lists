rule Backdoor_Win32_Sodager_B_2147646051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Sodager.B"
        threat_id = "2147646051"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Sodager"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "u_rotas_squid" ascii //weight: 3
        $x_4_2 = "TNDbSbzmScLcA29kPNHtRt9hBd1oRtXvBc5rT6zZRsvcQMTVTN9i8YmW8W" ascii //weight: 4
        $x_3_3 = " <<---- Ali o LInk do siga-me.txt" ascii //weight: 3
        $x_3_4 = {38 36 50 66 53 63 4c 74 4f 4d 6e 69 38 36 35 61 50 32 31 58 52 36 6e 6c 54 73 4c 61 53 37 39 6c 50 74 39 58 52 49 30 62 47 4c 31 47 48 34 35 4b 47 49 4c 53 49 71 39 49 45 [0-32] 50 4e 58 62 38 35 39 47 47 71 44 33}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Sodager_C_2147650011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Sodager.C"
        threat_id = "2147650011"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Sodager"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "u_rotas_squid" ascii //weight: 2
        $x_1_2 = "ScLdBcLuPI1XP6GW8aXBGrLSKszcT7TXScLSJMbZSczpRsPqN5TfRcHlTtDSGtLoScLkT5PbSdDfRsvSIMvqPN9kPNGWKsLqT6bkPtCY82zs845rT6z3RsvcQMTLScmWBsG" ascii //weight: 1
        $x_1_3 = "IKv6HKDKNr1IJrXPNr18GL9DIKv7Nm" ascii //weight: 1
        $x_1_4 = "N4TbSc5GSczuUKbkT6LoRcLqBd9bPm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

