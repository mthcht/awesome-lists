rule Ransom_Win32_Crypmodng_NKA_2147952496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crypmodng.NKA!MTB"
        threat_id = "2147952496"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crypmodng"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "encrypt file :" ascii //weight: 2
        $x_1_2 = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" ascii //weight: 1
        $x_1_3 = "C:\\Users\\Anti-Virus\\source\\repos\\ConsoleApplication4\\Release\\ConsoleApplication4.pdb" ascii //weight: 1
        $x_2_4 = {0f 28 ca 66 0f ef c8 0f 11 4c 05 e0 0f 10 44 05 f0 0f 28 ca 66 0f ef c2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

