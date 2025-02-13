rule PWS_Win32_Msnpass_B_2147596919_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Msnpass.B"
        threat_id = "2147596919"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Msnpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "?GetQQ@@YAKPAK@Z" ascii //weight: 10
        $x_10_2 = "KeyboardProc" ascii //weight: 10
        $x_5_3 = "installhook" ascii //weight: 5
        $x_5_4 = "msnmsgr" ascii //weight: 5
        $x_5_5 = "c:\\msnpass.txt" ascii //weight: 5
        $x_5_6 = "SetWindowsHookExA" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Msnpass_C_2147630163_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Msnpass.C"
        threat_id = "2147630163"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Msnpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "listerMsnContacts" ascii //weight: 3
        $x_2_2 = "Enviado=" wide //weight: 2
        $x_1_3 = "@Microsoft.msn.com >" wide //weight: 1
        $x_1_4 = "@terra.com.br>" wide //weight: 1
        $x_1_5 = "@oi.com.br>" wide //weight: 1
        $x_1_6 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Msnpass_D_2147633715_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Msnpass.D"
        threat_id = "2147633715"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Msnpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {38 30 30 34 38 38 32 33 0f 00 43 6f 64 65 20 64 65 72 72 65 75 72 20 3a 20}  //weight: 1, accuracy: Low
        $x_1_2 = {48 61 71 6d 73 6e 2e 61 73 70 3f 70 63 3d 16 00 75 73 65 72 33 2e 6a 61 62 72 79 2e 63 6f 6d 2f 70 72 6f 32 33 2f}  //weight: 1, accuracy: Low
        $x_1_3 = {26 70 6d 61 69 6c 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 70 77 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 6d 61 69 6c 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 63 6f 75 6e 74 72 79 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Msnpass_F_2147654384_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Msnpass.F"
        threat_id = "2147654384"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Msnpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\winsys\\msnl.txt" wide //weight: 1
        $x_1_2 = "c:\\winsys\\hotmail_" wide //weight: 1
        $x_1_3 = "173.212.238.196/msn/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Msnpass_B_2147806852_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Msnpass.B"
        threat_id = "2147806852"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Msnpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "49"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MSNpwdreg" ascii //weight: 10
        $x_10_2 = "software\\ngnsss" ascii //weight: 10
        $x_10_3 = "msnreord" ascii //weight: 10
        $x_5_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 5
        $x_5_5 = "\\shell\\open\\command" ascii //weight: 5
        $x_5_6 = "ShellExecuteA" ascii //weight: 5
        $x_2_7 = "msnmonitor.exe" ascii //weight: 2
        $x_2_8 = "msnkeyhook.dll" ascii //weight: 2
        $x_2_9 = "msnmonitor" ascii //weight: 2
        $x_2_10 = "installhook" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

