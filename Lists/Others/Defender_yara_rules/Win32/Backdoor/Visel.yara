rule Backdoor_Win32_Visel_A_2147597056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Visel.gen!A"
        threat_id = "2147597056"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Visel"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "130"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {81 ec 34 02 00 00 a1 ?? ?? 40 00 53 55 56 bd 01 00 00 00 55 68 ?? ?? 40 00 89 84 24 44 02 00 00 e8 ?? ?? ff ff 83 c4 08 8d 44 24 18 50 6a 28 c7 44 24 20 00 00 00 00 ff 15 ?? ?? 40 00 50 ff 15 ?? ?? 40 00 85 c0 74 4a 8d 4c 24 20 51 68 ?? ?? 40 00 6a 00 ff 15 ?? ?? 40 00 85 c0 74 34 8b 54 24 20 8b 44 24 24 6a 00 6a 00 6a 10 8d 4c 24 34 51 89 54 24 3c 8b 54 24 28 6a 00 52 89 6c 24 40 89 44 24 48 c7 44 24 4c 02 00 00 00 ff 15 28 b0 40 00 8d 44 24 38 50 8d 4c 24 20 51 6a 00 68 3f 00 0f 00 6a 00 68 ?? ?? 40 00 6a 00 68 ?? ?? 40 00 68 02 00 00 80 ff 15 ?? ?? 40 00}  //weight: 100, accuracy: Low
        $x_1_2 = "d:\\Works\\ByShell_Up19" ascii //weight: 1
        $x_1_3 = "byshell_bypass_sys\\bypass\\i386\\bypass.pdb" ascii //weight: 1
        $x_1_4 = "ByShell_Up19\\DarkShell\\Release\\DarkShell.pdb" ascii //weight: 1
        $x_1_5 = "_B_y_s_h_e_l_l_" ascii //weight: 1
        $x_1_6 = "ByShell_Event_Wait" ascii //weight: 1
        $x_1_7 = "Software\\SteelKernel" ascii //weight: 1
        $x_1_8 = "SteelKernelGroup" ascii //weight: 1
        $x_10_9 = "ZwCreateFile" ascii //weight: 10
        $x_10_10 = "ntkrnlpa.exe" ascii //weight: 10
        $x_10_11 = "ntoskrnl.exe" ascii //weight: 10
        $x_10_12 = "ntkrpamp.exe" ascii //weight: 10
        $x_10_13 = "ntkrnlmp.exe" ascii //weight: 10
        $x_10_14 = "KeServiceDescriptorTable" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Visel_C_2147598041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Visel.C"
        threat_id = "2147598041"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Visel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "29"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "md.exe /c \"%s\"" ascii //weight: 1
        $x_1_2 = "[Num Lock]" ascii //weight: 1
        $x_1_3 = "[Down]" ascii //weight: 1
        $x_1_4 = "[Right]" ascii //weight: 1
        $x_1_5 = "[Left]" ascii //weight: 1
        $x_1_6 = "[PageDown]" ascii //weight: 1
        $x_1_7 = "[End]" ascii //weight: 1
        $x_1_8 = "[Del]" ascii //weight: 1
        $x_1_9 = "[PageUp]" ascii //weight: 1
        $x_1_10 = "[Home]" ascii //weight: 1
        $x_1_11 = "[Insert]" ascii //weight: 1
        $x_1_12 = "[Scroll Lock]" ascii //weight: 1
        $x_1_13 = "[Print Screen]" ascii //weight: 1
        $x_1_14 = "[WIN]" ascii //weight: 1
        $x_1_15 = "[CTRL]" ascii //weight: 1
        $x_1_16 = "[TAB]" ascii //weight: 1
        $x_1_17 = "[F12]" ascii //weight: 1
        $x_1_18 = "[F11]" ascii //weight: 1
        $x_1_19 = "[F10]" ascii //weight: 1
        $x_1_20 = "[ESC]" ascii //weight: 1
        $x_1_21 = "<Enter>" ascii //weight: 1
        $x_1_22 = "<Back>" ascii //weight: 1
        $x_1_23 = "---Internet Explorer---" ascii //weight: 1
        $x_1_24 = "passworD" ascii //weight: 1
        $x_1_25 = "svchost.exe" ascii //weight: 1
        $x_1_26 = "Winlogon.exe" wide //weight: 1
        $x_1_27 = "\\Program Files\\Internet Explorer\\iexplore.exe" wide //weight: 1
        $x_1_28 = "My Capture Window" wide //weight: 1
        $x_1_29 = "Accept: */*" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Visel_F_2147625166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Visel.F"
        threat_id = "2147625166"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Visel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://xfdnf.5151j.com.cn/dnf.txt" wide //weight: 1
        $x_1_2 = "/ann/back.htm" wide //weight: 1
        $x_1_3 = "[gameQQAddr]" wide //weight: 1
        $x_1_4 = "Doo.exe" wide //weight: 1
        $x_1_5 = "2c49f800-c2dd-11cf-9ad6-0080c7e7b78d" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Visel_F_2147625166_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Visel.F"
        threat_id = "2147625166"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Visel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 00 6e 00 6a 00 65 00 63 00 74 00 [0-16] 55 00 52 00 4c 00 44 00 4e 00 53 00 [0-16] 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 [0-16] 44 00 69 00 73 00 70 00 6c 00 61 00 79 00 4e 00 61 00 6d 00 65 00 [0-16] 53 00 65 00 72 00 76 00 69 00 63 00 65 00 4e 00 61 00 6d 00 65 00 [0-16] 46 00 69 00 6c 00 65 00 4e 00 61 00 6d 00 65 00 [0-16] 49 00 70 00 5f 00 50 00 6f 00 72 00 74 00 [0-16] 49 00 70 00 [0-16] 43 00 6f 00 6e 00 66 00 69 00 67 00 [0-16] 55 00 72 00 6c 00 [0-16] 64 00 61 00 74 00 [0-16] 5c 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6b 6d 64 2e 65 78 65 20 2f 63 20 22 25 73 22 [0-6] 5c 00 6b 00 6d 00 64 00 2e 00 65 00 78 00 65 00 [0-6] 5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "My Capture Window" wide //weight: 1
        $x_1_4 = {7e 00 4d 00 48 00 7a 00 [0-16] 48 00 41 00 52 00 44 00 57 00 41 00 52 00 45 00 5c 00 44 00 45 00 53 00 43 00 52 00 49 00 50 00 54 00 49 00 4f 00 4e 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 5c 00 43 00 65 00 6e 00 74 00 72 00 61 00 6c 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 6f 00 72 00 5c 00 30 00}  //weight: 1, accuracy: Low
        $x_1_5 = {44 6f 77 6e 43 74 72 6c 41 6c 74 44 65 6c [0-16] 57 00 69 00 6e 00 6c 00 6f 00 67 00 6f 00 6e 00 2e 00 65 00 78 00 65}  //weight: 1, accuracy: Low
        $x_1_6 = "Xrat_DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

