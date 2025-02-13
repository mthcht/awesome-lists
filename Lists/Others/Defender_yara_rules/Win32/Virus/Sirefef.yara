rule Virus_Win32_Sirefef_A_2147631617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Sirefef.gen!A"
        threat_id = "2147631617"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "hScUn" ascii //weight: 1
        $x_1_2 = {8b 75 0c 8b 46 04 57 6a 5c 50 ff 15 ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? [0-4] 85 c0 75 0a}  //weight: 1, accuracy: Low
        $x_1_3 = {56 8a 0a 6b c0 21 0f be f1 33 c6 42 84 c9 75 f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Sirefef_A_2147631617_1
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Sirefef.gen!A"
        threat_id = "2147631617"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "hScUn" ascii //weight: 1
        $x_1_2 = {8b 75 0c 8b 46 04 57 6a 5c 50 ff 15 ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? [0-4] 85 c0 75 0a}  //weight: 1, accuracy: Low
        $x_1_3 = {56 8a 0a 6b c0 21 0f be f1 33 c6 42 84 c9 75 f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Sirefef_R_2147657890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Sirefef.R"
        threat_id = "2147657890"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 46 fe ff ff 85 c0 7c 11 8b 45 fc 66 39 70 06 74 08 56 56 56 83 c0 0c ff d0 68 00 80 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Sirefef_R_2147657890_1
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Sirefef.R"
        threat_id = "2147657890"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 46 fe ff ff 85 c0 7c 11 8b 45 fc 66 39 70 06 74 08 56 56 56 83 c0 0c ff d0 68 00 80 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

