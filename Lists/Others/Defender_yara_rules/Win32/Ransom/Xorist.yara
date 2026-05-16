rule Ransom_Win32_Xorist_SU_2147769516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Xorist.SU!MTB"
        threat_id = "2147769516"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Xorist"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "0p3nSOurc3 X0r157" ascii //weight: 1
        $x_1_2 = "motherfucker!" ascii //weight: 1
        $x_1_3 = "pussylicker" ascii //weight: 1
        $x_1_4 = "HOW TO DECRYPT FILES.txt" ascii //weight: 1
        $x_1_5 = "Attention! All your files were encrypted!" ascii //weight: 1
        $x_1_6 = "You have reached a limit of attempts - your data is irrevocably broken." ascii //weight: 1
        $x_1_7 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e [0-6] 41 6c 63 6d 65 74 65 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

