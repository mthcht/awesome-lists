rule Trojan_Win32_RansomLCRYX_BSA_2147941459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RansomLCRYX.BSA!MTB"
        threat_id = "2147941459"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RansomLCRYX"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "340"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "objShell.ShellExecute" wide //weight: 1
        $x_10_2 = "elevated" wide //weight: 10
        $x_1_3 = "WshShell.RegWrite" wide //weight: 1
        $x_1_4 = "DisableTaskMgr" wide //weight: 1
        $x_1_5 = "DisallowRun" wide //weight: 1
        $x_1_6 = "msconfig.exe" wide //weight: 1
        $x_1_7 = "Autoruns.exe" wide //weight: 1
        $x_1_8 = "gpedit.msc" wide //weight: 1
        $x_2_9 = "procexp.exe" wide //weight: 2
        $x_20_10 = "Set-MpPreference -DisableRealtimeMonitoring" wide //weight: 20
        $x_1_11 = "objShell.Run" wide //weight: 1
        $x_40_12 = {42 00 69 00 74 00 64 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 [0-36] 2d 00 64 00 69 00 73 00 61 00 62 00 6c 00 65 00}  //weight: 40, accuracy: Low
        $x_40_13 = {4b 00 61 00 73 00 70 00 65 00 72 00 73 00 6b 00 79 00 [0-50] 64 00 69 00 73 00 61 00 62 00 6c 00 65 00}  //weight: 40, accuracy: Low
        $x_20_14 = "PLEASEREADME.txt" wide //weight: 20
        $x_200_15 = "LCRYPTORX RANSOMWARE" wide //weight: 200
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

