rule Ransom_Win32_GENTLEMEN_DA_2147973231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GENTLEMEN.DA!MTB"
        threat_id = "2147973231"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GENTLEMEN"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 2d ad 77 3a e7 d0 a9 af c3 98 e2 63 9a 38 98 50 f8 f2 84 9b a6 ef 69 d9 06 83 bb cf d6 48 0c 0b 53 97 14 17 6d b0 65 73 35 5d 6f 40 6b 53 ba 7a d7 b3 66 d8 05 7a 58 de f8 5a 8e fb 53 fb ea}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

