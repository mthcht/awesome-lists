rule Virus_Win32_Fakefire_A_2147599249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Fakefire.A"
        threat_id = "2147599249"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakefire"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Program Files\\Microsoft Visual Studio\\VB98\\pjtbinder.vbp" wide //weight: 1
        $x_1_2 = "regsvr32.exe /s scrrun.dll" wide //weight: 1
        $x_1_3 = "c:\\vbvirus\\ownerprotect.ptt" wide //weight: 1
        $x_1_4 = "\\spfirewall.exe" wide //weight: 1
        $x_1_5 = "\\spinst.exe" wide //weight: 1
        $x_1_6 = "+\"sd.exe -c q -pn" wide //weight: 1
        $x_1_7 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\FileProtector" wide //weight: 1
        $x_1_8 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\RegSCRLib" wide //weight: 1
        $x_1_9 = ":\\spRepair.exe" wide //weight: 1
        $x_1_10 = "s.Run \"cm\" & \"d.ex\" & \"e\" & \" /c\" & \"dat\" & \"e 2050-12-31\" , vbHide" wide //weight: 1
        $x_1_11 = "Navapw32.exe" ascii //weight: 1
        $x_1_12 = "Navapsvc.exe" ascii //weight: 1
        $x_1_13 = "KAV32.exe" ascii //weight: 1
        $x_1_14 = "KvXP.kxp" ascii //weight: 1
        $x_1_15 = "RAVmon.exe" ascii //weight: 1
        $x_1_16 = "Iparmor.exe" ascii //weight: 1
        $x_1_17 = "TrojanHunter.exe" ascii //weight: 1
        $x_1_18 = "ZONEALARM.EXE" ascii //weight: 1
        $x_1_19 = "SAFEWEB.EXE" ascii //weight: 1
        $x_1_20 = "NORMIST.EXE" ascii //weight: 1
        $x_1_21 = "FPROT.EXE" ascii //weight: 1
        $x_1_22 = "CLEANER.EXE" ascii //weight: 1
        $x_1_23 = "AVP32.EXE" ascii //weight: 1
        $x_1_24 = "vsmon.exe" ascii //weight: 1
        $x_1_25 = "defendio.exe" ascii //weight: 1
        $x_1_26 = "360safe.exe" ascii //weight: 1
        $x_1_27 = "maxthon.exe" ascii //weight: 1
        $x_1_28 = "opera.exe" ascii //weight: 1
        $x_1_29 = "fleInfect" ascii //weight: 1
        $x_1_30 = "MicrosoftAllFileFirewall" ascii //weight: 1
        $x_1_31 = "C:\\Program Files\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii //weight: 1
        $x_1_32 = "sistema de XP) sobre el sistema de Windows de la" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Fakefire_A_2147599249_1
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Fakefire.A"
        threat_id = "2147599249"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakefire"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[FireWall Messages]" ascii //weight: 1
        $x_1_2 = "If other antivirus programs denied MSFirewall from" ascii //weight: 1
        $x_1_3 = "normally running please run \"srRepair.exe\" to Repair or" ascii //weight: 1
        $x_1_4 = "Uninstall other antivirus solutions." ascii //weight: 1
        $x_1_5 = "Wenn andere Kostenz?hler-Viren-Software die Microsoft" ascii //weight: 1
        $x_1_6 = "Brandmauerbewegung bitte, um andere Anti-virus softwares" ascii //weight: 1
        $x_1_7 = "zu schlie?en verhinderte und spRepair.exe durchzuf" ascii //weight: 1
        $x_1_8 = "spRepair.exe" ascii //weight: 1
        $x_1_9 = "Ravtimer.exe" ascii //weight: 1
        $x_1_10 = "Iparmor.exe" ascii //weight: 1
        $x_1_11 = "TrojanHunter.exe" ascii //weight: 1
        $x_1_12 = "THGUARD.EXE" ascii //weight: 1
        $x_1_13 = "navw32.EXE" ascii //weight: 1
        $x_1_14 = "KAVPFW.EXE" ascii //weight: 1
        $x_1_15 = "KAV32.exe" ascii //weight: 1
        $x_1_16 = "Rising.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Fakefire_A_2147601508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Fakefire.gen!A"
        threat_id = "2147601508"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakefire"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c4 0c c7 45 fc 0b 00 00 00 6a 00 68 ?? ?? ?? ?? 8d 4d ?? 51 ff 15 ?? ?? ?? ?? 8d 55 ?? 52 8d 45 ?? 50 ff 15 ?? ?? ?? ?? c7 45 fc 0c 00 00 00 c7 85 ?? ff ff ff ?? ?? ?? ?? c7 85 ?? ff ff ff 08 00 00 00 c7 85 ?? ff ff ff ?? ?? ?? ?? c7 85 ?? ff ff ff 08 00 00 00 b8 10 00 00 00}  //weight: 10, accuracy: Low
        $x_10_2 = {89 41 0c 6a 02 68 ?? ?? ?? ?? 8d 4d ?? 51 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 83 c4 2c c7 45 fc 0d 00 00 00 8b 55 08 66 c7 42 50 01 00 c7 45 fc 0e 00 00 00 ba ?? ?? ?? ?? 8d 4d ?? ff 15 ?? ?? ?? ?? c7 45 fc 0f 00 00 00}  //weight: 10, accuracy: Low
        $x_1_3 = {5c 00 6f 00 77 00 6e 00 65 00 72 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 2e 00 70 00 74 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {3a 00 5c 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {77 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 53 00 68 00 65 00 6c 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {52 00 65 00 67 00 77 00 72 00 69 00 74 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {2a 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {63 00 64 00 65 00 66 00 67 00 68 00 69 00 6a 00 6b 00 6c 00 6d 00 6e 00 6f 00 70 00 71 00 72 00 73 00 74 00 75 00 76 00 77 00 78 00 79 00 7a 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Virus_Win32_Fakefire_B_2147601823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Fakefire.B"
        threat_id = "2147601823"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakefire"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "37"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c7 45 f0 00 00 00 00 c7 45 f4 00 00 00 00 8b 45 08 8b 08 8b 55 08 52 ff 51 04 c7 45 fc 01 00 00 00 c7 45 fc 02 00 00 00 6a ff ff 15 ?? ?? 40 00 c7 45 fc 03 00 00 00 6a 00 68 ?? ?? 40 00 8d 45 88 50 ff 15 ?? ?? 40 00 8d 4d 88 51 8d 55 c0 52 ff 15 ?? ?? 40 00 c7 45 fc 04 00 00 00 c7 85 60 ff ff ff 01 00 00 00 c7 85 58 ff ff ff 02 00 00 00 c7 85 50 ff ff ff 14 00 00 00 c7 85 48 ff ff ff 02 00 00 00 c7 85 40 ff ff ff 01 00 00 00 c7 85 38 ff ff ff 02 00 00 00 8d 85 58 ff ff ff 50 8d 8d 48 ff ff ff 51 8d 95 38 ff ff ff 52 8d 85 c8 fe ff ff 50 8d 8d d8 fe ff ff 51 8d 55 b0 52}  //weight: 10, accuracy: Low
        $x_10_2 = "MSVBVM60.DLL" ascii //weight: 10
        $x_2_3 = "Msfirewall" wide //weight: 2
        $x_2_4 = "C:\\VBVirus\\" wide //weight: 2
        $x_2_5 = ".ptt" wide //weight: 2
        $x_2_6 = "*.exe" wide //weight: 2
        $x_2_7 = "\\Set1.Ico" wide //weight: 2
        $x_2_8 = "C:\\Program Files\\Microsoft Visual Studio\\VB98\\pjt" wide //weight: 2
        $x_2_9 = "regsvr32.exe /s scrrun.dll" wide //weight: 2
        $x_2_10 = "Outlook.Application" wide //weight: 2
        $x_1_11 = "fleInfect" ascii //weight: 1
        $x_1_12 = "fleFuck" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 8 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Virus_Win32_Fakefire_C_2147601825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Fakefire.C"
        threat_id = "2147601825"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakefire"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\Program Files\\Microsoft Visual Studio\\VB98\\pjtAwsVariantioner.vbp" wide //weight: 1
        $x_1_2 = "MSFirewall" wide //weight: 1
        $x_1_3 = "wscript.Shell" wide //weight: 1
        $x_1_4 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_5 = "del c:\\vbvirus" wide //weight: 1
        $x_1_6 = ".ptt" wide //weight: 1
        $x_1_7 = "Infect" wide //weight: 1
        $x_1_8 = ".exe , .dll , .Ocx , .Scr" wide //weight: 1
        $x_1_9 = "Paint.NET v3.10" ascii //weight: 1
        $x_1_10 = {89 85 78 ff ff ff eb 0a c7 85 78 ff ff ff 00 00 00 00 6a 00 6a 00 8b 45 dc 50 68 ?? ?? 40 00 ff 15 ?? ?? 40 00 8b d0 8d 4d d4 ff 15 ?? ?? 40 00 50 8d 4d d0 51 ff 15 ?? ?? 40 00 50 68 ?? ?? 40 00 8d 55 d8 52 ff 15 ?? ?? 40 00 50 6a 00 e8 ?? ?? ff ff ff 15 ?? ?? 40 00 8d 45 d0 50 8d 4d d4 51 8d 55 d8 52 8d 45 dc 50 6a 04}  //weight: 1, accuracy: Low
        $x_1_11 = {8d 8d 7c ff ff ff 8d 95 6c ff ff ff 51 8d 85 5c ff ff ff 52 50 c7 85 14 ff ff ff ?? ?? 40 00 c7 85 0c ff ff ff 08 80 00 00 ff 15 ?? ?? 40 00 8d 8d 0c ff ff ff 50 51 ff 15 ?? ?? 40 00 66 89 85 cc fe ff ff 8d 95 5c ff ff ff 8d 85 6c ff ff ff 52 8d 8d 7c ff ff ff 50 51 6a 03 ff 15 ?? ?? 40 00 83 c4 10 66 39 9d cc fe ff ff 0f 84 5c 01 00 00 8b 4d 08 8b 45 e8 8d 95 d8 fe ff ff 53 52 8b 11 50 52 89 9d d8 fe ff ff e8 ?? ?? ff ff ff d6 8b 55 08 8b 4d a0 8d 45 ec 53 50 8b 02 6a 04 51 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule Virus_Win32_Fakefire_D_2147604731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Fakefire.D"
        threat_id = "2147604731"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakefire"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pjtBinder" ascii //weight: 1
        $x_1_2 = "spRepair.exe" ascii //weight: 1
        $x_1_3 = "Sub Infecting Module" ascii //weight: 1
        $x_1_4 = "C:\\Program Files\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii //weight: 1
        $x_1_5 = "fleFuck" ascii //weight: 1
        $x_1_6 = "fleInfect" ascii //weight: 1
        $x_1_7 = "C:\\Program Files\\Microsoft Visual Studio\\VB98\\pjtbinder.vbp" wide //weight: 1
        $x_1_8 = "#.exe" wide //weight: 1
        $x_1_9 = "regsvr32.exe /s scrrun.dll" wide //weight: 1
        $x_1_10 = "MSfirewall" wide //weight: 1
        $x_1_11 = "c:\\vbvirus\\ownerprotect.ptt" wide //weight: 1
        $x_1_12 = "\\Set1.Ico" wide //weight: 1
        $x_1_13 = "Unable to modify directories in target executable.  File may not contain any icon resources." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

