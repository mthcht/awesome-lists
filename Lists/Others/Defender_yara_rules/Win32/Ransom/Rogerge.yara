rule Ransom_Win32_Rogerge_A_2147769794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Rogerge.A"
        threat_id = "2147769794"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Rogerge"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 [0-255] 64 00 6c 00 6c 00 72 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 73 00 65 00 72 00 76 00 65 00 72 00 20 00 [0-8] 2d 00}  //weight: 3, accuracy: Low
        $x_2_2 = "-pedokremez" wide //weight: 2
        $x_2_3 = "-nomimikatz" wide //weight: 2
        $x_2_4 = "-plocklist" wide //weight: 2
        $x_1_5 = "-killrdp" wide //weight: 1
        $x_1_6 = "-greetings" wide //weight: 1
        $x_1_7 = "-norename" wide //weight: 1
        $x_1_8 = "-append=" wide //weight: 1
        $x_1_9 = "-multiproc" wide //weight: 1
        $x_1_10 = "--samba" wide //weight: 1
        $x_1_11 = "--full" wide //weight: 1
        $x_1_12 = "--fast=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Rogerge_A_2147769794_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Rogerge.A"
        threat_id = "2147769794"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Rogerge"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 [0-255] 64 00 6c 00 6c 00 72 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 73 00 65 00 72 00 76 00 65 00 72 00 20 00 [0-8] 2d 00}  //weight: 3, accuracy: Low
        $x_2_2 = "-nomimikatz" wide //weight: 2
        $x_2_3 = "-pedokremez" wide //weight: 2
        $x_2_4 = "-plocklist" wide //weight: 2
        $x_1_5 = "-killrdp" wide //weight: 1
        $x_1_6 = "-greetings" wide //weight: 1
        $x_1_7 = "-norename" wide //weight: 1
        $x_1_8 = "-append=" wide //weight: 1
        $x_1_9 = "-multiproc" wide //weight: 1
        $x_1_10 = "--samba" wide //weight: 1
        $x_1_11 = "--full" wide //weight: 1
        $x_1_12 = "--fast=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

