rule HackTool_Win32_Patcher_E_2147654807_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Patcher.E"
        threat_id = "2147654807"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Patcher"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 75 08 8b 7d 0c eb 06 8a 06 aa 83 c6 02 66 83 3e 00 75 f4 c6 07 00 8b 45 0c}  //weight: 1, accuracy: High
        $x_1_2 = ".snr_offsets.ldr" ascii //weight: 1
        $x_1_3 = "\\regpatch.reg" ascii //weight: 1
        $x_1_4 = "Watermark Patcher" ascii //weight: 1
        $x_1_5 = "created with dUP2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Patcher_2147744922_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Patcher!MTB"
        threat_id = "2147744922"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Patcher"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Cracker Jack" ascii //weight: 1
        $x_1_2 = "Inline patch" ascii //weight: 1
        $x_1_3 = "Patchtarget" ascii //weight: 1
        $x_1_4 = "RadStudio XE7 Patch " ascii //weight: 1
        $x_1_5 = "Activation Patch " ascii //weight: 1
        $x_1_6 = "file patched" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Patcher_2147744922_1
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Patcher!MTB"
        threat_id = "2147744922"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Patcher"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CrackingPatching" ascii //weight: 1
        $x_1_2 = "IDMan.exe" ascii //weight: 1
        $x_1_3 = "install IDM Patch" ascii //weight: 1
        $x_1_4 = "crackingpatching.com" ascii //weight: 1
        $x_1_5 = "Internet Download Manager" ascii //weight: 1
        $x_1_6 = "combobox" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Patcher_2147744922_2
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Patcher!MTB"
        threat_id = "2147744922"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Patcher"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DosRAR" ascii //weight: 1
        $x_1_2 = "Apply registration-name" ascii //weight: 1
        $x_1_3 = "Liq69ers" ascii //weight: 1
        $x_1_4 = "Polish Medical Mailing Sp. z o.o." ascii //weight: 1
        $x_1_5 = "Crack" ascii //weight: 1
        $x_1_6 = "write of illegal authenticy information" ascii //weight: 1
        $x_1_7 = "WinRAR Cracker Edition Patch" ascii //weight: 1
        $x_1_8 = "Patch succeeded!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Patcher_AMTB_2147934306_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Patcher!AMTB"
        threat_id = "2147934306"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Patcher"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DiaLog*ezt" ascii //weight: 1
        $x_1_2 = "xxPzrgmz" ascii //weight: 1
        $x_1_3 = "NG Prackw>4Id@-" ascii //weight: 1
        $n_100_4 = "Uninst.exe" ascii //weight: -100
        $n_100_5 = "Uninstaller.exe" ascii //weight: -100
        $n_100_6 = "Uninstal.exe" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule HackTool_Win32_Patcher_AMTB_2147934306_1
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Patcher!AMTB"
        threat_id = "2147934306"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Patcher"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Patch created by Tola's Patching Engine" wide //weight: 1
        $n_100_2 = "Uninst.exe" ascii //weight: -100
        $n_100_3 = "Uninstaller.exe" ascii //weight: -100
        $n_100_4 = "Uninstal.exe" ascii //weight: -100
        $n_100_5 = "MultiExtractor.exe" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule HackTool_Win32_Patcher_SGA_2147959661_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Patcher.SGA!AMTB"
        threat_id = "2147959661"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Patcher"
        severity = "High"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Successfully patched !" ascii //weight: 1
        $x_1_2 = "Patching failed !" ascii //weight: 1
        $x_1_3 = "This Patch will rock ParetoLogic Anti-Virus PLUS 7.0" ascii //weight: 1
        $x_1_4 = "New Tiger [AoRE-Team]" ascii //weight: 1
        $n_100_5 = "Uninst.exe" ascii //weight: -100
        $n_100_6 = "Uninstaller.exe" ascii //weight: -100
        $n_100_7 = "Uninstal.exe" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

