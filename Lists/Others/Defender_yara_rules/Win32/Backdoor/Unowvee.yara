rule Backdoor_Win32_Unowvee_STB_2147782873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Unowvee.STB"
        threat_id = "2147782873"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Unowvee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/timeout/voip.aspx" ascii //weight: 1
        $x_1_2 = "%ls?guid=%ls&v=%ls&cg=%ls" ascii //weight: 1
        $x_1_3 = "BotVersion" ascii //weight: 1
        $x_1_4 = "%.2d:%.2d %.2d-%\\BaseNamedObject" ascii //weight: 1
        $x_1_5 = "%APPDATA%\\XProfiles" ascii //weight: 1
        $x_1_6 = "Agent_VX_" ascii //weight: 1
        $x_1_7 = "cdn.nvbcloud.com" ascii //weight: 1
        $x_1_8 = "Select * From AntiVirusProduct" ascii //weight: 1
        $x_1_9 = {43 6f 6d 6d 61 6e 64 00 4e 45 57 00 54 41 53 4b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Win32_Unowvee_STC_2147782876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Unowvee.STC!!Unowvee.STC"
        threat_id = "2147782876"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Unowvee"
        severity = "Critical"
        info = "Unowvee: an internal category used to refer to some threats"
        info = "STC: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/timeout/voip.aspx" ascii //weight: 1
        $x_1_2 = "%ls?guid=%ls&v=%ls&cg=%ls" ascii //weight: 1
        $x_1_3 = "BotVersion" ascii //weight: 1
        $x_1_4 = "%.2d:%.2d %.2d-%\\BaseNamedObject" ascii //weight: 1
        $x_1_5 = "%APPDATA%\\XProfiles" ascii //weight: 1
        $x_1_6 = "Agent_VX_" ascii //weight: 1
        $x_1_7 = "cdn.nvbcloud.com" ascii //weight: 1
        $x_1_8 = "Select * From AntiVirusProduct" ascii //weight: 1
        $x_1_9 = {43 6f 6d 6d 61 6e 64 00 4e 45 57 00 54 41 53 4b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Win32_Unowvee_LOWFIA_2147782953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Unowvee.LOWFIA"
        threat_id = "2147782953"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Unowvee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 2e 58 66 [0-10] 6a 70 58 66 [0-10] 6a 6e 58 66 [0-10] 6a 67}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 14 07 8b cf 83 e1 01 80 c2 05 32 54 ?? ?? 88 14 07 47 3b fe 7c}  //weight: 1, accuracy: Low
        $x_1_3 = {6e 6e 6a 6a c7 [0-10] 6a 68 62 6e c7 [0-10] 4b 76 30 30 c7 [0-10] 6d 35 47 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win32_Unowvee_LOWFIB_2147782954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Unowvee.LOWFIB"
        threat_id = "2147782954"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Unowvee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\KnownDlls32\\ntdll.dll" wide //weight: 1
        $x_1_2 = "\\KnownDlls32\\kernel32.dll" wide //weight: 1
        $x_1_3 = "\\KnownDlls32\\crypt32.dll" wide //weight: 1
        $x_1_4 = "\\KnownDlls\\ntdll.dll" wide //weight: 1
        $x_1_5 = "\\KnownDlls\\kernel32.dll" wide //weight: 1
        $x_1_6 = "\\KnownDlls\\crypt32.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

