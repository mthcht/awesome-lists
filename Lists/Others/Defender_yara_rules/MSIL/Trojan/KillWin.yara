rule Trojan_MSIL_KillWin_ATM_2147780818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KillWin.ATM!MTB"
        threat_id = "2147780818"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KillWin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "/k color 47 && takeown /f C:\\Windows\\System32 && icacls C:\\Windows\\System32 /grant %username%:F &&" wide //weight: 5
        $x_5_2 = "takeown /f C:\\Windows\\System32\\drivers && icacls C:\\Windows\\System32\\drivers /grant %username%:F && Exit" wide //weight: 5
        $x_3_3 = "DisableTaskMgr" ascii //weight: 3
        $x_3_4 = "C:\\Windows\\System32\\hal.dll" ascii //weight: 3
        $x_3_5 = "C:\\Windows\\System32\\ci.dll" ascii //weight: 3
        $x_3_6 = "C:\\Windows\\System32\\winload.exe" ascii //weight: 3
        $x_3_7 = "C:\\Windows\\System32\\drivers\\disk.sys" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_KillWin_MA_2147901446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KillWin.MA!MTB"
        threat_id = "2147901446"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KillWin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HACKED" wide //weight: 1
        $x_1_2 = "DisableTaskMgr" wide //weight: 1
        $x_1_3 = "/k taskkill /f /im taskmgr.exe && exit" wide //weight: 1
        $x_1_4 = "system_destroy" ascii //weight: 1
        $x_1_5 = "Start_BSOD" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_7 = "EnterDebugMode" ascii //weight: 1
        $x_1_8 = "Hallo, It looks like you downloaded virus and your system is on your risk!" wide //weight: 1
        $x_1_9 = "And it's your fault" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_KillWin_SWR_2147927260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KillWin.SWR!MTB"
        threat_id = "2147927260"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KillWin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Virus_Destructive\\obj\\Release\\Virus_Destructive.pdb" ascii //weight: 2
        $x_1_2 = "tmr_next_payload_Tick" ascii //weight: 1
        $x_1_3 = "$6b612611-d8f4-4f0f-a158-43d15bf5d557" ascii //weight: 1
        $x_1_4 = "Virus_Destructive.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_KillWin_SWT_2147927261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KillWin.SWT!MTB"
        threat_id = "2147927261"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KillWin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Payload_start_Load" ascii //weight: 2
        $x_2_2 = "READY TO DIE?!" wide //weight: 2
        $x_2_3 = "tv_noise_dirty" wide //weight: 2
        $x_1_4 = "DisableTaskMgr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_KillWin_SWS_2147935871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KillWin.SWS!MTB"
        threat_id = "2147935871"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KillWin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 02 16 02 8e 69 6f 62 00 00 0a 09 6f 63 00 00 0a de 0a 09 2c 06 09 6f 39 00 00 0a dc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_KillWin_ARR_2147969211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KillWin.ARR!MTB"
        threat_id = "2147969211"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KillWin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f" ascii //weight: 6
        $x_4_2 = "add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableTaskMgr /t REG_DWORD /d 1 /f" ascii //weight: 4
        $x_5_3 = "add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableRegistryTools /t REG_DWORD /d 1 /f" ascii //weight: 5
        $x_15_4 = "Malware_Destructive.Properties.Resources" ascii //weight: 15
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_15_*) and 1 of ($x_5_*))) or
            ((1 of ($x_15_*) and 1 of ($x_6_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_KillWin_A_2147978315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KillWin.A!MTB"
        threat_id = "2147978315"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KillWin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "HACKED" wide //weight: 20
        $x_20_2 = "Hacked by" wide //weight: 20
        $x_11_3 = "Global\\MG_Prank_8B2F" wide //weight: 11
        $x_2_4 = "/create /f /sc minute /mo 1 /tn" wide //weight: 2
        $x_2_5 = "/f /im svchost.exe" wide //weight: 2
        $x_2_6 = "mbr.bin" wide //weight: 2
        $x_2_7 = "\\\\.\\GLOBALROOT\\Device\\Harddisk3\\DR3" wide //weight: 2
        $x_2_8 = ":\\EFI\\Microsoft\\Boot\\bootmgr.efi" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_11_*) and 5 of ($x_2_*))) or
            ((2 of ($x_20_*) and 1 of ($x_2_*))) or
            ((2 of ($x_20_*) and 1 of ($x_11_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_KillWin_AMTB_2147978704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KillWin!AMTB"
        threat_id = "2147978704"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KillWin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HACKED BY quraish" ascii //weight: 1
        $x_3_2 = "Global\\MG_Prank_8B2F" ascii //weight: 3
        $x_3_3 = "abolhb.com" ascii //weight: 3
        $x_1_4 = "StartBomb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

