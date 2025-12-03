rule Ransom_Win64_Rhysida_MA_2147847825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Rhysida.MA!MTB"
        threat_id = "2147847825"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhysida"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CriticalBreachDetected.pdf" ascii //weight: 1
        $x_1_2 = {76 69 73 69 74 20 6f 75 72 20 73 65 63 75 72 65 20 70 6f 72 74 61 6c 3a 20 72 68 79 73 69 64 61 [0-101] 2e 6f 6e 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_3 = "cmd.exe /c reg delete \"HKCU\\Conttol Panel\\Desktop\" /v Wallpaper /f" ascii //weight: 1
        $x_1_4 = "cmd.exe /c start powershell.exe -WindowStyle Hidden -Command Sleep -Milliseconds 500; Remove-Item -Force -Path" ascii //weight: 1
        $x_1_5 = "file_to_crypt size [%ld] bytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Rhysida_YAA_2147852008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Rhysida.YAA!MTB"
        threat_id = "2147852008"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhysida"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "%PDF-1.4" ascii //weight: 10
        $x_1_2 = "cybersecurity team Rhysida" ascii //weight: 1
        $x_1_3 = "with your secret key" ascii //weight: 1
        $x_1_4 = "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\ActiveDesktop\" /v NoChangingWallPaper /t REG_SZ /d 1 /f" ascii //weight: 1
        $x_1_5 = "vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Rhysida_C_2147852717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Rhysida.C!dha"
        threat_id = "2147852717"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhysida"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Rhysida" ascii //weight: 1
        $x_1_2 = "C:/Windows/Fonts/Arial.ttf" ascii //weight: 1
        $x_1_3 = "C:/Users/Public/bg.jpg" ascii //weight: 1
        $x_1_4 = "It's vital to note that any attempts to decrypt the encrypted files independently could lead to permanent data loss." ascii //weight: 1
        $x_1_5 = {54 6f 20 75 74 69 6c 69 7a 65 20 74 68 69 73 20 6b 65 79 2c 20 76 69 73 69 74 20 6f 75 72 20 73 65 63 75 72 65 20 70 6f 72 74 61 6c 3a 20 [0-255] 6f 6e 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Rhysida_NRA_2147958760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Rhysida.NRA!MTB"
        threat_id = "2147958760"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhysida"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Rhysida-0.3" ascii //weight: 2
        $x_1_2 = "GetProcessMemoryInfo" ascii //weight: 1
        $x_1_3 = "EnumProcesses" ascii //weight: 1
        $x_1_4 = "AES Encrypt" ascii //weight: 1
        $x_2_5 = {48 0f bd c2 48 83 f0 3f 85 c0 89 c3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

