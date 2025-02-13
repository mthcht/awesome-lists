rule TrojanDownloader_Win32_Serortat_B_2147687048_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Serortat.B"
        threat_id = "2147687048"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Serortat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "**-**-**-**12321**-*123*-*2342**-**12322**-**23**-**-**-**" ascii //weight: 1
        $x_1_2 = "83UE4JIH3XS1SCBVOL2R77NZWEBZ6U05JGOOZPMI2TAO5ELU3PN334A4ADC3YJO8YUK2ASMV6ER434F1F1IMOFFIUKAHRJ" ascii //weight: 1
        $x_1_3 = "5DM5NFWGEB1FHI20W5A9V9C8AAY0GWNPGX3S8NYE0L7RI1JDEH3MKWYRJOSCT9IZ16KJGXD8VP7PX23EU9X1LDYBCPPPBA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Serortat_B_2147687048_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Serortat.B"
        threat_id = "2147687048"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Serortat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "94C40A2BDE2D160C090E64C5C4AF9E8DEB6BD535345ABE6388AD67D4419C5CF1067EA957F1" ascii //weight: 2
        $x_2_2 = "1EBE0021D43B200673949A9FFE64D1412710729190FE19C96382B3A0BC1029BE3428DF0127" ascii //weight: 2
        $x_2_3 = "87D77FA652B8AD95B021D569E91DC1679E42EF106CF85F82EB1A3BEA4095508E36DD053BE24BEB19C0" ascii //weight: 2
        $x_1_4 = "F10041FB094FF817" ascii //weight: 1
        $x_1_5 = "75F10B28D015CD7895" ascii //weight: 1
        $x_1_6 = "7FFD43E562E2012FE96A85" ascii //weight: 1
        $x_1_7 = "8AE61EC57683BD6F9C3CF334" ascii //weight: 1
        $x_1_8 = "54AF2CCF015682F60366E37A" ascii //weight: 1
        $x_1_9 = "037CC3799B3AE31E32" ascii //weight: 1
        $x_1_10 = "2CA1DA15C40179E552B344E365" ascii //weight: 1
        $x_2_11 = "4FA427F41BB36A82F91C1211007B91B8719A468F5146" ascii //weight: 2
        $x_2_12 = "205BF93DF46E9642274899598F9AF919DF1FC70334A2" ascii //weight: 2
        $x_2_13 = "1A5FFD2DD374AA453C42280B1A112BD61338EB519681" ascii //weight: 2
        $x_1_14 = "BE29B97DA133270E3882AE478B" ascii //weight: 1
        $x_1_15 = "C7205CFA0A" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

