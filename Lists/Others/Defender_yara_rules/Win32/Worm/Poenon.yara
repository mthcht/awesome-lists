rule Worm_Win32_Poenon_A_2147647885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Poenon.A"
        threat_id = "2147647885"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Poenon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "policies\\Explorer /v NoDriveTypeAutoRun /t REG_DWORD /d :000000ff /f" wide //weight: 1
        $x_1_2 = ":\\$Tmp\\clean.exe" wide //weight: 1
        $x_1_3 = "label=PENDRIVE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Poenon_A_2147647885_1
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Poenon.A"
        threat_id = "2147647885"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Poenon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "policies\\Explorer /v NoDriveTypeAutoRun /t REG_DWORD /d :000000ff /f" wide //weight: 1
        $x_1_2 = "Policies\\System /v DisableTaskMgr /t REG_DWORD /d 1 /f" wide //weight: 1
        $x_1_3 = "shell\\Open\\command=$windows" wide //weight: 1
        $x_1_4 = "shell\\Open\\Default=1" wide //weight: 1
        $x_1_5 = "label=PENDRIVE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Poenon_B_2147650342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Poenon.B"
        threat_id = "2147650342"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Poenon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "net user %username% * /RANDOM" wide //weight: 1
        $x_1_2 = "HideMyIpSrv" wide //weight: 1
        $x_1_3 = "$windowsWipe.bat" wide //weight: 1
        $x_1_4 = "creater of this" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Poenon_C_2147650448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Poenon.C"
        threat_id = "2147650448"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Poenon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 06 17 d6 13 06 00 11 06 11 07 8e b7 fe 04 13 11 11 11 2d de 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 13 09 16 13 08 2b 14 11 09 11 08 9a 0b 07 6f ?? ?? ?? ?? 00 11 08 17 d6 13 08 00 11 08 11 09 8e b7 fe 04 13 11 11 11 2d de 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 13 0b 16 13 0a 2b 14 11 0b 11 0a 9a 0c 08 6f ?? ?? ?? ?? 00 11 0a 17 d6 13 0a 00 11 0a 11 0b 8e b7 fe 04 13 11 11 11 2d de 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 13 0d 16 13 0c 2b 14}  //weight: 1, accuracy: Low
        $x_1_2 = {20 f4 01 00 00 6a 28 ?? ?? ?? ?? 00 28 ?? ?? ?? ?? 0b 07 08 da 20 f4 01 00 00 6a fe 04 0d 09 2c 04 17 0a 2b 03}  //weight: 1, accuracy: Low
        $x_1_3 = "\\Desktop\\WormWin32  Poenon." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

