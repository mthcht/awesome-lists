rule Trojan_Win32_Drolnux_DA_2147779329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Drolnux.DA!MTB"
        threat_id = "2147779329"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Drolnux"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 74 24 27 8d 94 24 20 a0 05 00 c6 44 24 20 4d c6 44 24 21 5a c6 44 24 22 90 c6 44 24 23 00 c6 44 24 24 03 c6 44 24 25 00 c6 44 24 26 00}  //weight: 1, accuracy: High
        $x_1_2 = {c6 44 24 27 00 0f b6 c8 8d 44 24 28}  //weight: 1, accuracy: High
        $x_1_3 = {8d bc 27 00 00 00 00 28 08 83 c0 01 39 d0 75}  //weight: 1, accuracy: High
        $x_1_4 = "%c:\\.RECYCLER\\%ls.exe" ascii //weight: 1
        $x_1_5 = "Moonchild Productions" ascii //weight: 1
        $x_1_6 = "Amishell" ascii //weight: 1
        $x_1_7 = "aHR0cDovL2IzLmdlLnR0L2dldHQvNVhidFp2YjIvbnNzMy5nej9pbmRleD0x" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Drolnux_RF_2147888287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Drolnux.RF!MTB"
        threat_id = "2147888287"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Drolnux"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 8b 44 24 20 09 c0 0f 85 72 01 00 00 8b 43 3c 8d 74 24 3c c7 44 24 08 02 00 00 00 31 ff 89 74 24 0c 01 d8 89 c6 89 44 24 1c 8b 40 54 89 1c 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

