rule PWS_Win32_Phorex_A_2147598871_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Phorex.A"
        threat_id = "2147598871"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sfc_os.dll" ascii //weight: 1
        $x_1_2 = "%s\\drivers\\tcpip.sys" ascii //weight: 1
        $x_3_3 = {6d 61 69 6c 74 6f 3a 00 68 72 65 66}  //weight: 3, accuracy: High
        $x_1_4 = "transfer-encoding" ascii //weight: 1
        $x_3_5 = "right\">%dKb</td>" ascii //weight: 3
        $x_4_6 = {5b 50 55 31 70 5d 00 00 5b 53 4c 31 5d}  //weight: 4, accuracy: High
        $x_1_7 = "runescape" ascii //weight: 1
        $x_3_8 = {6c 6e 6b 00 64 6c 6c 00 65 78 65 00}  //weight: 3, accuracy: High
        $x_3_9 = {25 73 5c 63 66 67 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 2 of ($x_1_*))) or
            ((4 of ($x_3_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_3_*))) or
            (all of ($x*))
        )
}

