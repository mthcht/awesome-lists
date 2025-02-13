rule Ransom_Win64_SolasoCrypt_MK_2147772212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/SolasoCrypt.MK!MTB"
        threat_id = "2147772212"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "SolasoCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "READ_ME_TO_RECOVER_YOUR_FILES.txt" ascii //weight: 1
        $x_1_2 = "your files were encrypted and are currently unusable" ascii //weight: 1
        $x_1_3 = "Your computer ID is:" ascii //weight: 1
        $x_1_4 = {65 6d 61 69 6c 3a [0-20] 40 62 75 78 6f 64 2e 63 6f 6d}  //weight: 1, accuracy: Low
        $x_1_5 = "exe|msi|doc|docx|xls|xlsx|xlsm|ppt|pdf|jpg|jpeg|png|rar|7z|zip|bdf" ascii //weight: 1
        $x_1_6 = ".solaso" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_SolasoCrypt_AJY_2147772356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/SolasoCrypt.AJY!MSR"
        threat_id = "2147772356"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "SolasoCrypt"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "__READ_ME_PLEASE.txt__" ascii //weight: 1
        $x_1_2 = "Hello, you cant open your files." ascii //weight: 1
        $x_1_3 = "The only way to open and use your files again is using a tool that only we have." ascii //weight: 1
        $x_1_4 = "email: sammy70p_y61m@buxod.com" ascii //weight: 1
        $x_1_5 = "C:\\Users\\MARIO\\source\\repos\\ENCRIPTAR\\x64\\Release\\ENCRIPTAR.pdb" ascii //weight: 1
        $x_1_6 = ".solaso" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_SolasoCrypt_PA_2147772517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/SolasoCrypt.PA!MTB"
        threat_id = "2147772517"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "SolasoCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "\\__READ.txt" ascii //weight: 3
        $x_3_2 = "\\__READ_ME_TO_RECOVER_YOUR_FILES.txt" ascii //weight: 3
        $x_1_3 = "cmd.exe /C Del /f /q \"%s" wide //weight: 1
        $x_1_4 = "exe|msi|doc|docx|xls|xlsx|xlsm|ppt|pdf|jpg|jpeg|png|rar" ascii //weight: 1
        $x_1_5 = ".solaso" ascii //weight: 1
        $x_1_6 = {5c 45 4e 43 52 49 50 54 41 52 5c [0-4] 5c [0-16] 5c 45 4e 43 52 49 50 54 41 52 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

