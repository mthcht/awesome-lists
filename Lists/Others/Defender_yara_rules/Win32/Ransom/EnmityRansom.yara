rule Ransom_Win32_EnmityRansom_YAA_2147918917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/EnmityRansom.YAA!MTB"
        threat_id = "2147918917"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "EnmityRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 d2 33 b4 d0 08 c0 00 00 33 8c d0 0c c0 00 00 33 b4 07 08 a0 00 00 33 8c 07 0c a0 00 00 33 b4 03 08 e0 00 00 8b 55 c8 33 8c 03 0c e0 00 00 8b de 89 75 08}  //weight: 2, accuracy: High
        $x_1_2 = "Enmity\\Release\\Enmity.pdb" ascii //weight: 1
        $x_1_3 = "C:\\keyforunlock\\Key.txt" ascii //weight: 1
        $x_1_4 = "C:\\keyforunlock\\RSAdecr.keys" ascii //weight: 1
        $x_1_5 = "information.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

