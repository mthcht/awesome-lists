rule Trojan_Win32_Ofisus_A_2147731060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ofisus.A"
        threat_id = "2147731060"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ofisus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\cmd.exe" wide //weight: 1
        $x_1_2 = "@http://" wide //weight: 1
        $x_1_3 = "'.Split('@');" wide //weight: 1
        $x_1_4 = "+'.exe';" wide //weight: 1
        $x_1_5 = "}}catch{}} " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ofisus_A_2147731060_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ofisus.A"
        threat_id = "2147731060"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ofisus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\cmd.exe" wide //weight: 1
        $x_1_2 = "cmd /c powershell" wide //weight: 1
        $x_1_3 = ").downloadfile($" wide //weight: 1
        $x_1_4 = "''%tmp%\\" wide //weight: 1
        $x_1_5 = "'');start-process" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ofisus_A_2147731060_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ofisus.A"
        threat_id = "2147731060"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ofisus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\cmd.exe" wide //weight: 1
        $x_1_2 = {2f 00 63 00 [0-16] 73 00 65 00 54 00 20 00}  //weight: 1, accuracy: Low
        $x_1_3 = {26 00 26 00 [0-16] 50 00 4f 00 77 00 45 00 72 00 53 00 68 00 65 00 4c 00 4c 00}  //weight: 1, accuracy: Low
        $x_1_4 = {2d 00 66 00 [0-8] 27 00}  //weight: 1, accuracy: Low
        $x_1_5 = ").Invoke(" wide //weight: 1
        $x_1_6 = "::fromBASe64STRInG(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Ofisus_A_2147731060_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ofisus.A"
        threat_id = "2147731060"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ofisus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {3b 00 29 00 27 00 40 00 27 00 28 00 74 00 69 00 6c 00 70 00 53 00 2e 00 27 00 [0-96] 2f 00 2f 00 3a 00 70 00 74 00 74 00 68 00 40 00}  //weight: 10, accuracy: Low
        $x_1_2 = "}}{hctac}}" wide //weight: 1
        $x_1_3 = {27 00 65 00 78 00 65 00 2e 00 27 00 2b 00 [0-16] 24 00 2b 00 27 00 5c 00 27 00 2b 00 70 00 6d 00 65 00 74 00 3a 00 76 00 6e 00 65 00 24 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_4 = {27 00 65 00 78 00 65 00 2e 00 [0-16] 5c 00 27 00 2b 00 29 00 28 00 68 00 74 00 61 00 50 00 70 00 6d 00 65 00 54 00 74 00 65 00 47 00 3a 00 3a 00 5d 00 68 00 74 00 61 00 50 00 2e 00 4f 00 49 00 2e 00 6d 00 65 00 74 00 73 00 79 00 53 00 5b 00 28 00 3d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ofisus_A_2147731060_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ofisus.A"
        threat_id = "2147731060"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ofisus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\cmd.exe" wide //weight: 1
        $x_1_2 = "& /K CD C: & PowerShell -EncodedCommand dAByAHkA" wide //weight: 1
        $x_2_3 = {5c 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 20 00 2d 00 4e 00 6f 00 50 00 20 00 2d 00 45 00 78 00 65 00 63 00 20 00 42 00 79 00 70 00 61 00 73 00 73 00 20 00 2d 00 45 00 43 00 20 00 4a 00 41 00 42 00 70 00 41 00 47 00 34 00 41 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ofisus_A_2147731060_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ofisus.A"
        threat_id = "2147731060"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ofisus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00 63 00 3a 00 5c 00 [0-32] 5c 00 [0-32] 5c 00 [0-32] 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 25 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 3a 00 7e 00 30 00 2c 00 31 00 25 00 25 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 3a 00 7e 00 39 00 2c 00 32 00 25 00 20 00 2f 00 56 00 3a 00 [0-8] 2f 00 43 00 73 00}  //weight: 10, accuracy: Low
        $x_1_2 = "&&for " wide //weight: 1
        $x_1_3 = {29 00 64 00 6f 00 20 00 73 00 65 00 74 00 20 00 [0-8] 3d 00 21 00 [0-8] 21 00 21 00 [0-8] 3a 00 7e 00 25 00 ?? ?? 2c 00 31 00 21 00 26 00 26 00 69 00 66 00 20 00 25 00}  //weight: 1, accuracy: Low
        $x_1_4 = {3a 00 7e 00 25 00 5e 00 ?? ?? 2c 00 31 00 21 00 26 00 26 00}  //weight: 1, accuracy: Low
        $x_1_5 = "$&&^f^or" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ofisus_A_2147731060_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ofisus.A"
        threat_id = "2147731060"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ofisus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\cmd.exe" wide //weight: 1
        $x_1_2 = "cMd.EXE /c poWerShelL.exe -ec KABOAGUAdwAtAE8A" wide //weight: 1
        $x_1_3 = "cmd.exe /c powershell.exe -NoP -EC JABpAG4AcwB0AGEA" wide //weight: 1
        $x_1_4 = "cMd.eXe /c p^o^w^e^r^s^h^E^L^L^.^e^x^e^ ^-^e^c^ ^K^A^B^O^" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Ofisus_A_2147731202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ofisus.gen!A"
        threat_id = "2147731202"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ofisus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00 63 00 3a 00 5c 00 [0-32] 5c 00 [0-32] 5c 00 [0-32] 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00}  //weight: 1, accuracy: Low
        $x_1_2 = "s^e^t " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ofisus_A_2147731202_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ofisus.gen!A"
        threat_id = "2147731202"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ofisus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "\\cmd.exe" wide //weight: 3
        $x_1_2 = "s^e^t " wide //weight: 1
        $x_1_3 = "c^m^d" wide //weight: 1
        $x_1_4 = {3d 00 21 00 [0-16] 21 00 21 00 [0-16] 3a 00 7e 00}  //weight: 1, accuracy: Low
        $x_1_5 = {31 00 21 00 26 00 26 00 [0-2] 69 00 [0-2] 66 00}  //weight: 1, accuracy: Low
        $x_1_6 = {21 00 26 00 26 00 [0-2] 73 00 [0-2] 65 00 [0-2] 74 00}  //weight: 1, accuracy: Low
        $x_1_7 = "(^set " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ofisus_A_2147731202_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ofisus.gen!A"
        threat_id = "2147731202"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ofisus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "\\cmd.exe" wide //weight: 5
        $x_1_2 = "$SHeLLid[1]+$ShellId[13]+'x'" wide //weight: 1
        $x_1_3 = "[strIng]$verBOsEpreFeRence)[1,3]+'X'-JoiN''" wide //weight: 1
        $x_1_4 = "$VERbOsEprEFErence.TOsTRIng()[1,3]+'x'-jOIn''" wide //weight: 1
        $x_1_5 = {24 00 50 00 73 00 48 00 4f 00 6d 00 45 00 5b 00 [0-4] 5d 00 2b 00 24 00 70 00 53 00 48 00 6f 00 6d 00 65 00 5b 00 [0-4] 5d 00 2b 00 27 00 58 00 27 00}  //weight: 1, accuracy: Low
        $x_1_6 = {24 00 45 00 6e 00 56 00 3a 00 63 00 6f 00 6d 00 53 00 50 00 65 00 43 00 5b 00 [0-4] 2c 00 [0-4] 2c 00 [0-4] 5d 00 2d 00 4a 00 4f 00 69 00 4e 00 27 00 27 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ofisus_A_2147731202_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ofisus.gen!A"
        threat_id = "2147731202"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ofisus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00 63 00 3a 00 5c 00 [0-32] 5c 00 [0-32] 5c 00 [0-32] 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 25 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 3a 00 7e 00 30 00 2c 00 31 00 25 00 25 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 3a 00 7e 00 39 00 2c 00 32 00 25 00 20 00 2f 00 56 00}  //weight: 3, accuracy: Low
        $x_1_2 = "\\cmd.exe" wide //weight: 1
        $x_1_3 = "%aLLuSErSProFILe:~" wide //weight: 1
        $x_1_4 = "%aPpDatA:~" wide //weight: 1
        $x_1_5 = "%COmMonpRograMFIlEs(X86):~" wide //weight: 1
        $x_1_6 = "%CommonpROgRAMfIles:~" wide //weight: 1
        $x_1_7 = "%COMMonproGRAMw6432:~" wide //weight: 1
        $x_1_8 = "%LocALappData:~" wide //weight: 1
        $x_1_9 = "%ProgramData:~" wide //weight: 1
        $x_1_10 = "%PrOgrAMfILES(x86):~" wide //weight: 1
        $x_1_11 = "%PROgRAMFIlES:~" wide //weight: 1
        $x_1_12 = "%PUbliC:~" wide //weight: 1
        $x_1_13 = "%SESSIONNAME:~" wide //weight: 1
        $x_1_14 = "%SYSTeMRoot:~" wide //weight: 1
        $x_1_15 = "%TeMP:~" wide //weight: 1
        $x_1_16 = "%tMP:~" wide //weight: 1
        $x_1_17 = "%windir:~" wide //weight: 1
        $x_2_18 = " & %^c^o^m^S^p^E^c^% %^c^o^m^S^p^E^c^% /V /c set %" wide //weight: 2
        $x_1_19 = {3d 00 21 00 [0-16] 21 00 21 00 [0-16] 3a 00 7e 00}  //weight: 1, accuracy: Low
        $x_1_20 = {26 00 26 00 20 00 53 00 45 00 74 00 [0-32] 3d 00 21 00 [0-16] 3a 00 [0-8] 3d 00 [0-4] 21 00 26 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ofisus_B_2147731692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ofisus.gen!B"
        threat_id = "2147731692"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ofisus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\cmd.exe" wide //weight: 1
        $x_1_2 = "POwErsHell" wide //weight: 1
        $x_1_3 = " -W" wide //weight: 1
        $x_1_4 = "{1}" wide //weight: 1
        $x_1_5 = "-f" wide //weight: 1
        $x_1_6 = ").Invoke(" wide //weight: 1
        $x_1_7 = ".GETFIE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ofisus_B_2147731692_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ofisus.gen!B"
        threat_id = "2147731692"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ofisus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\cmd.exe" wide //weight: 1
        $x_1_2 = "PowersHell" wide //weight: 1
        $x_1_3 = ".DownloadString('http://" wide //weight: 1
        $x_1_4 = "IEX" wide //weight: 1
        $x_1_5 = " -wiNdoWs HiDdEN " wide //weight: 1
        $x_1_6 = " -noNI" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ofisus_B_2147731692_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ofisus.gen!B"
        threat_id = "2147731692"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ofisus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "powershell" wide //weight: 5
        $x_5_2 = ".DownloadFile(" wide //weight: 5
        $x_5_3 = "'http://" wide //weight: 5
        $x_5_4 = ".exe'" wide //weight: 5
        $x_1_5 = " -w 1 " wide //weight: 1
        $x_1_6 = " -WindowStyle Hidden " wide //weight: 1
        $x_1_7 = "Start-Process " wide //weight: 1
        $x_1_8 = ".ShellExecute(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ofisus_B_2147731692_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ofisus.gen!B"
        threat_id = "2147731692"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ofisus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "\\powershell.exe" wide //weight: 5
        $x_1_2 = "$SHeLLid[1]+$ShellId[13]+'x'" wide //weight: 1
        $x_1_3 = ")[1,3]+'X'-JoiN''" wide //weight: 1
        $x_1_4 = {24 00 50 00 73 00 48 00 4f 00 6d 00 45 00 5b 00 [0-4] 5d 00 2b 00 24 00 70 00 53 00 48 00 6f 00 6d 00 65 00 5b 00 [0-4] 5d 00 2b 00 27 00 58 00 27 00}  //weight: 1, accuracy: Low
        $x_1_5 = {24 00 45 00 6e 00 56 00 3a 00 63 00 6f 00 6d 00 53 00 50 00 65 00 43 00 5b 00 [0-4] 2c 00 [0-4] 2c 00 [0-4] 5d 00 2d 00 4a 00 4f 00 69 00 4e 00 27 00 27 00}  //weight: 1, accuracy: Low
        $x_1_6 = {53 00 56 00 [0-8] 27 00 6f 00 46 00 73 00 27 00 [0-8] 27 00 [0-8] 27 00 29 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ofisus_B_2147734551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ofisus.B"
        threat_id = "2147734551"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ofisus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5c 00 6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 00 00 43 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 20 00 68 00 74 00 74 00 70 00}  //weight: 2, accuracy: High
        $x_2_2 = {5c 00 6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 00 00 6d 00 73 00 68 00 74 00 61 00 20 00 68 00 74 00 74 00 70 00}  //weight: 2, accuracy: High
        $x_1_3 = ".hta" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

