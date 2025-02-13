rule TrojanSpy_Win32_Serortat_B_2147696518_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Serortat.B"
        threat_id = "2147696518"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Serortat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "83UE4JIH3XS1SCBVOL2R77NZWEBZ6U05JGOOZPMI2TAO5ELU3PN334A4ADC3YJO8YUK2ASMV6ER434F1F1IMOFFIUKAHRJ" ascii //weight: 1
        $x_1_2 = "5DM5NFWGEB1FHI20W5A9V9C8AAY0GWNPGX3S8NYE0L7RI1JDEH3MKWYRJOSCT9IZ16KJGXD8VP7PX23EU9X1LDYBCPPPBA" ascii //weight: 1
        $x_1_3 = {4c 6f 67 69 6e 3a [0-32] 53 65 6e 68 61 3a [0-32] 49 45 39 5f 44 65 63 6f 64 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

