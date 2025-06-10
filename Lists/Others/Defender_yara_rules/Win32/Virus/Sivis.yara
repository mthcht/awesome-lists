rule Virus_Win32_Sivis_YAE_2147943237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Sivis.YAE!MTB"
        threat_id = "2147943237"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Sivis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 3a 2f 65 78 70 2f 00 76 69 73 75 61 00 2e 2e 00 20 5b 46 69 6c 65 5d 20}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4c b0 4c 8b 54 b0 08 57 8b 78 04 c1 c9 ?? 03 4c b8 4c c1 ca ?? 03 54 b8 08 89 4c b0 08}  //weight: 1, accuracy: Low
        $x_10_3 = {69 d2 fb b4 a9 53 29 c0 40 2b c2 89 41 44 69 c0 fb b4 a9 53 29 d2 42 2b d0 52 58}  //weight: 10, accuracy: High
        $x_10_4 = {68 14 00 00 00 68 00 00 00 00 68 b8 56 40 00 e8 fc 0f 00 00 83 c4 ?? 68 00 00 00 00 e8 f5 0f 00 00 a3 bc 56 40 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

