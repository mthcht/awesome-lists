rule Ransom_Win32_Filecoder_A_2147688309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.A"
        threat_id = "2147688309"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 07 30 04 39 8a 07 30 04 2f 47 4b 75}  //weight: 1, accuracy: High
        $x_1_2 = {03 ca 6a 10 8a 04 0e 30 01 42 58 3b d0 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_PA_2147744357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.PA!MTB"
        threat_id = "2147744357"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Name of your explain.txt" wide //weight: 1
        $x_1_2 = "\\How_To_Decrypt_Files.txt" wide //weight: 1
        $x_1_3 = "Hi! your important files were encrypted!" wide //weight: 1
        $x_1_4 = "Your Files Encrypted." wide //weight: 1
        $x_1_5 = "Victim name" wide //weight: 1
        $x_1_6 = "Spartan Crypter" wide //weight: 1
        $x_1_7 = ".crypt" wide //weight: 1
        $x_1_8 = ".EncryptedBySpartan78" wide //weight: 1
        $x_1_9 = "/C choice /C Y /N /D Y /T 3 & Del " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win32_Filecoder_SA_2147745181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.SA!MSR"
        threat_id = "2147745181"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sleep" ascii //weight: 1
        $x_1_2 = "GetDriveType" ascii //weight: 1
        $x_1_3 = "WriteFile" ascii //weight: 1
        $x_1_4 = "ONCE RANSOM PAID" ascii //weight: 1
        $x_1_5 = "CAN RECOVER" ascii //weight: 1
        $x_1_6 = "YOUR FILES EASILY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_SA_2147745181_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.SA!MSR"
        threat_id = "2147745181"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "kwvhrdibgmmpkhkidrby4mccwqpds5za6uo2thcw5gz75qncv7rbhyad.onion" ascii //weight: 2
        $x_1_2 = "Bypass Kremez" wide //weight: 1
        $x_1_3 = "ako-readme.txt" wide //weight: 1
        $x_1_4 = "ENCRYPTED FILES" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Filecoder_2147750106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder!MSR"
        threat_id = "2147750106"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jerry_glanville_data@aol.com" wide //weight: 1
        $x_1_2 = "HOW_TO_RECOVERY_FILES.txt" wide //weight: 1
        $x_1_3 = "Dr.Web" wide //weight: 1
        $x_1_4 = "Kaspersky Lab" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_2147750106_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder!MSR"
        threat_id = "2147750106"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Decrypt Instructions.txt" wide //weight: 1
        $x_1_2 = "Death\\obj\\Release\\ssvchost.pdb" ascii //weight: 1
        $x_1_3 = "All of your files are encrypted" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_PF_2147751541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.PF!MTB"
        threat_id = "2147751541"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 55 fc c6 04 02 00 c6 00 00 8a 14 06 2a d1 fe ca 88 14 07 41 40 3b 4d f8 76}  //weight: 4, accuracy: High
        $x_1_2 = {8b 08 8b f1 c1 ee ?? 33 f1 69 f6 ?? ?? ?? ?? 03 f2 89 70 04 83 c0 04 42 3d ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_PF_2147751541_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.PF!MTB"
        threat_id = "2147751541"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "README_encrypted.txt" ascii //weight: 1
        $x_1_2 = "_encrypted" ascii //weight: 1
        $x_1_3 = "ATTENTION!!! ALL YOUR FILES HAVE BEEN ENCRYPTED" ascii //weight: 1
        $x_1_4 = "YOU HAVE TO PAY $1000 DOLLARS TO UNLOCK YOUR FILES" ascii //weight: 1
        $x_1_5 = "RANSOMWARE_KDF_INFO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win32_Filecoder_PG_2147751828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.PG!MTB"
        threat_id = "2147751828"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "If you want restore your files write on email" ascii //weight: 1
        $x_1_2 = "In the subject write - id-0521${CODE}" ascii //weight: 1
        $x_1_3 = "Do not try to recover data, it's wasting your time." ascii //weight: 1
        $x_1_4 = "Every 7 days the price doubles." ascii //weight: 1
        $x_1_5 = "\\!=How_recovery_files=!.txt" wide //weight: 1
        $x_1_6 = {2e 00 73 00 71 00 6c 00 [0-10] 2e 00 6d 00 64 00 66 00 [0-10] 2e 00 74 00 78 00 74 00 [0-10] 2e 00 64 00 62 00 66 00 [0-10] 2e 00 63 00 6b 00 70 00 [0-10] 2e 00 64 00 61 00 63 00 70 00 61 00 63 00 [0-10] 2e 00 64 00 62 00 33 00 [0-10] 2e 00 64 00 74 00 78 00 73 00 [0-10] 2e 00 6d 00 64 00 74 00 [0-10] 2e 00 73 00 64 00 66 00 [0-10] 2e 00 4d 00 44 00 46 00 [0-10] 2e 00 44 00 42 00 46 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_AR_2147752230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.AR!MTB"
        threat_id = "2147752230"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "vssadmin delete shadows /all /quiet" ascii //weight: 10
        $x_10_2 = "\\RESTORE_DLL_FILES.HTML" ascii //weight: 10
        $x_10_3 = "\\delete.bat" ascii //weight: 10
        $x_1_4 = "ThreatExpert Sucks!" ascii //weight: 1
        $x_1_5 = "\" goto Repeat" ascii //weight: 1
        $x_1_6 = "Ransom.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Filecoder_PH_2147752642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.PH!MTB"
        threat_id = "2147752642"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your personal files are being locked" ascii //weight: 1
        $x_1_2 = "ExtensionsToEncrypt" wide //weight: 1
        $x_1_3 = ".aaf .aep .aepx .plb .prel .prproj .aet .ppj .psd" ascii //weight: 1
        $x_1_4 = "EncryptFiles" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_PI_2147753029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.PI!MTB"
        threat_id = "2147753029"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender" ascii //weight: 1
        $x_1_2 = "DisableAntiSpyware" ascii //weight: 1
        $x_1_3 = "svhost.exe" ascii //weight: 1
        $x_1_4 = "The terrible virus has captured your files" ascii //weight: 1
        $x_1_5 = "C:\\Decoder.hta" ascii //weight: 1
        $x_1_6 = "Your files are encrypted a unique ID" ascii //weight: 1
        $x_1_7 = "This will inevitably lead to permanent data loss" ascii //weight: 1
        $x_1_8 = "Data recovery.hta" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win32_Filecoder_YA_2147754302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.YA!MTB"
        threat_id = "2147754302"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Geminis3's(R) Ransominator" ascii //weight: 1
        $x_1_2 = "encrypted with \"military grade\"" ascii //weight: 1
        $x_1_3 = "decryption key to get lost" ascii //weight: 1
        $x_1_4 = "LeaveCriticalSection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_E_2147757717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.E!MTB"
        threat_id = "2147757717"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "runner" ascii //weight: 1
        $x_2_2 = "/deletevalue {current} safeboot" ascii //weight: 2
        $x_1_3 = "bcdedit.exe" ascii //weight: 1
        $x_2_4 = "/C shutdown /r /f /t 0" ascii //weight: 2
        $x_5_5 = "X/MHvS8r2rsf+xMoFoVuXNN9VP7QeQZAsvpVldZEujE=" ascii //weight: 5
        $x_1_6 = "tomnom" ascii //weight: 1
        $x_1_7 = "Windows.old" ascii //weight: 1
        $x_1_8 = "tNVRMD" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Filecoder_F_2147757718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.F!MTB"
        threat_id = "2147757718"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "testRansome.pdb" ascii //weight: 1
        $x_1_2 = "Data.txt" ascii //weight: 1
        $x_1_3 = "RansomewareInfoBackup" ascii //weight: 1
        $x_1_4 = ".txt.doc.docx.xls.xlsx.ppt.pptx.pst.ost.msg.em.vsd.vsdx.csv.rtf.123.wks.wk1.pdf.dwg.onetoc2.snt.docb.docm.dot.dotm.dotx.xlsm.xlsb.xlw.xlt.xlm." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Filecoder_G_2147757941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.G!MTB"
        threat_id = "2147757941"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "System.Security.Cryptography" ascii //weight: 1
        $x_1_2 = "Player login" wide //weight: 1
        $x_1_3 = "localhost" wide //weight: 1
        $x_1_4 = "SERVER=" wide //weight: 1
        $x_1_5 = ";DATABASE=" wide //weight: 1
        $x_1_6 = ";PASSWORD=" wide //weight: 1
        $x_1_7 = "get_FrucKrbNwEQZzWrtlAWdsXD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_KP_2147759111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.KP"
        threat_id = "2147759111"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CashCat.g.resources" ascii //weight: 1
        $x_1_2 = "CashCat.Properties.Resources.resources" ascii //weight: 1
        $x_2_3 = "CashCatRansomwareSimulator" ascii //weight: 2
        $x_1_4 = "\\Documents\\GitHub\\CashCatRansomwareSimulator\\CashCat\\obj\\Debug\\CashCat.pdb" ascii //weight: 1
        $x_1_5 = "CashCat.exe" ascii //weight: 1
        $x_1_6 = " The Single copy of the private key which allow you to decrypt the files is on a secret server on the internet dark web" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Filecoder_BA_2147762606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.BA!MTB"
        threat_id = "2147762606"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".CONTI" ascii //weight: 1
        $x_1_2 = "HOW_TO_DECRYPT.txt" ascii //weight: 1
        $x_1_3 = "$RECYCLE.BIN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_BA_2147762606_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.BA!MTB"
        threat_id = "2147762606"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ALL YOUR DATA WAS ENCRYPTED" ascii //weight: 1
        $x_1_2 = "__lock_XXX__" ascii //weight: 1
        $x_1_3 = "!!!READ_ME!!!.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_BA_2147762606_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.BA!MTB"
        threat_id = "2147762606"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "READ_ME.txt" ascii //weight: 1
        $x_1_2 = "cmd.exe /C ping 1.1.1.1 -n 10 -w 3000 > Nul & Del /f /q \"%s\"" ascii //weight: 1
        $x_2_3 = "c:\\111\\hermes\\cryptopp" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Filecoder_BA_2147762606_3
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.BA!MTB"
        threat_id = "2147762606"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "delete shadows /all /quiet" ascii //weight: 3
        $x_3_2 = "vssadmin.exe" ascii //weight: 3
        $x_1_3 = "READ_ME.TXT" ascii //weight: 1
        $x_1_4 = "HELP_PC.EZDZ-REMOVE.txt" ascii //weight: 1
        $x_1_5 = "encrypted_key.bin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Filecoder_BA_2147762606_4
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.BA!MTB"
        threat_id = "2147762606"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "HOW_TO_DECRYPT" ascii //weight: 1
        $x_1_2 = {54 00 68 00 65 00 20 00 [0-16] 20 00 69 00 73 00 20 00 4c 00 4f 00 43 00 4b 00 45 00 44 00}  //weight: 1, accuracy: Low
        $x_1_3 = {54 68 65 20 [0-16] 20 69 73 20 4c 4f 43 4b 45 44}  //weight: 1, accuracy: Low
        $x_1_4 = "@protonmail.com" ascii //weight: 1
        $x_1_5 = "For decryption KEY write HERE:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win32_Filecoder_BC_2147763470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.BC!MTB"
        threat_id = "2147763470"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "All of your files are encrypted" ascii //weight: 2
        $x_2_2 = "FenixIloveyou!!" ascii //weight: 2
        $x_2_3 = "-----BEGIN PUBLIC KEY-----" ascii //weight: 2
        $x_1_4 = "Cryptolocker.txt" ascii //weight: 1
        $x_1_5 = "Help to decrypt.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Filecoder_DD_2147763509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.DD!MTB"
        threat_id = "2147763509"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Your files are encrypted" ascii //weight: 1
        $x_1_2 = "All encrypted files for this computer has extension: .9465bb" ascii //weight: 1
        $x_1_3 = "Rebooting/shutdown will cause you to lose files without the possibility of recovery" ascii //weight: 1
        $x_1_4 = "Just open our website, upload the encrypted file and get the decrypted file for free" ascii //weight: 1
        $x_1_5 = {4f 70 65 6e 20 6f 75 72 20 77 65 62 73 69 74 65 3a 20 [0-60] 2e 6f 6e 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Filecoder_DD_2147763509_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.DD!MTB"
        threat_id = "2147763509"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All your files like photos, databases, documents and other important are encrypted with strongest encryption and unique key" ascii //weight: 1
        $x_1_2 = "The only method of recovering files is to purchase decrypt tool and unique key for you" ascii //weight: 1
        $x_1_3 = "You can send one of your encrypted file from your PC and we decrypt it for free" ascii //weight: 1
        $x_1_4 = "Please note that you'll never restore your data without payment" ascii //weight: 1
        $x_1_5 = "restoremanager@airmail.cc" ascii //weight: 1
        $x_1_6 = "https://we.tl/t-ccUfUrQOhF" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Filecoder_DD_2147763509_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.DD!MTB"
        threat_id = "2147763509"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ALL YOUR DOCUMENTS PHOTOS DATABASES AND OTHER IMPORTANT FILES HAVE BEEN ENCRYPTED" ascii //weight: 1
        $x_1_2 = "Your files are NOT damaged! Your files are modified only. This modification is reversible" ascii //weight: 1
        $x_1_3 = "The only 1 way to decrypt your files is to receive the private key and decryption program" ascii //weight: 1
        $x_1_4 = "Any attempts to restore your files with the third party software will be fatal for your files" ascii //weight: 1
        $x_1_5 = "To receive the private key and decryption program follow the instructions below" ascii //weight: 1
        $x_1_6 = {68 74 74 70 3a 2f 2f [0-30] 2e [0-20] 2e 6f 6e 69 6f 6e 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Filecoder_BD_2147763786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.BD!MTB"
        threat_id = "2147763786"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "delete shadows /all /quiet" ascii //weight: 3
        $x_3_2 = "sysnative\\vssadmin.exe" ascii //weight: 3
        $x_1_3 = "All your files have been encrypted" ascii //weight: 1
        $x_1_4 = "Your files are encrypted" ascii //weight: 1
        $x_1_5 = "babyfromparadise" ascii //weight: 1
        $x_1_6 = "cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Filecoder_BE_2147763891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.BE!MTB"
        threat_id = "2147763891"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "vssadmin delete shadows /all" ascii //weight: 3
        $x_3_2 = "Your All Files Encrypted With High level Cryptography Algorithm" ascii //weight: 3
        $x_1_3 = "@protonmail.com" ascii //weight: 1
        $x_1_4 = "Read-Me-Now.txt" ascii //weight: 1
        $x_1_5 = "If You Need Your Files You Should Pay For Decryption" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Filecoder_BF_2147764220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.BF!MTB"
        threat_id = "2147764220"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/c vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 2
        $x_2_2 = "All your files have been encrypted by us" ascii //weight: 2
        $x_1_3 = "How Recovery Files.txt" ascii //weight: 1
        $x_1_4 = "If you want restore files write on e-mail - jimmyneytron@tuta.io" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Filecoder_DG_2147764253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.DG!MTB"
        threat_id = "2147764253"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".rapid" ascii //weight: 1
        $x_1_2 = "! How Decrypt Files.txt" ascii //weight: 1
        $x_1_3 = "Decryptedd!" ascii //weight: 1
        $x_1_4 = "Test encrypt failed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_DG_2147764253_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.DG!MTB"
        threat_id = "2147764253"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".guesswho" ascii //weight: 1
        $x_1_2 = "Test decrypt failed" ascii //weight: 1
        $x_1_3 = "DECRYPTED" ascii //weight: 1
        $x_1_4 = "How Recovery Files.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_DG_2147764253_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.DG!MTB"
        threat_id = "2147764253"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/c vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 2
        $x_2_2 = ".rapid" ascii //weight: 2
        $x_1_3 = "How Recovery Files.txt" ascii //weight: 1
        $x_1_4 = "rapid@airmail.cc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Filecoder_DG_2147764253_3
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.DG!MTB"
        threat_id = "2147764253"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-----BEGIN PUBLIC KEY-----" ascii //weight: 1
        $x_1_2 = "-----END PUBLIC KEY-----" ascii //weight: 1
        $x_1_3 = "SCHTASKS /DELETE /TN " ascii //weight: 1
        $x_1_4 = "networkauto.top" ascii //weight: 1
        $x_1_5 = "gate.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_DH_2147764441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.DH!MTB"
        threat_id = "2147764441"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".crypt" ascii //weight: 1
        $x_1_2 = "Original File successfully deleted" ascii //weight: 1
        $x_1_3 = "RANSOM.txt" ascii //weight: 1
        $x_1_4 = "PAY ME BITCOIN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_DH_2147764441_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.DH!MTB"
        threat_id = "2147764441"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ooops, your homework has been encrypted!" ascii //weight: 1
        $x_1_2 = "WannaDecryptor" ascii //weight: 1
        $x_1_3 = ".shit" ascii //weight: 1
        $x_1_4 = "encryptFileName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_DH_2147764441_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.DH!MTB"
        threat_id = "2147764441"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "How__to__decrypt__files.txt" ascii //weight: 1
        $x_1_2 = "ITERATOR LIST CORRUPTED!" ascii //weight: 1
        $x_1_3 = "sicck@protonmail.com" ascii //weight: 1
        $x_1_4 = "BTC Wallet :" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_DH_2147764441_3
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.DH!MTB"
        threat_id = "2147764441"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c taskkill /f /im" ascii //weight: 1
        $x_1_2 = "cmd.exe /c ping 127.0.0.1>nul & del /q" ascii //weight: 1
        $x_1_3 = "cry_demo.dll" ascii //weight: 1
        $x_1_4 = "cmd_shadow" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_DH_2147764441_4
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.DH!MTB"
        threat_id = "2147764441"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "The network is LOCKED" ascii //weight: 1
        $x_1_2 = "For decryption tool write HERE:" ascii //weight: 1
        $x_1_3 = "If you do not pay, we will publish private data on our news site." ascii //weight: 1
        $x_1_4 = "@protonmail.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Filecoder_DH_2147764441_5
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.DH!MTB"
        threat_id = "2147764441"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "How_To_Decrypt.txt" ascii //weight: 1
        $x_1_2 = ".ini.encrypted" ascii //weight: 1
        $x_1_3 = "We can garantee what we can decrypt any your file" ascii //weight: 1
        $x_1_4 = "we will decrypt and show some part of decrypted file" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_DH_2147764441_6
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.DH!MTB"
        threat_id = "2147764441"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mARASUF@cock.li" ascii //weight: 1
        $x_1_2 = "!INFO.HTA" ascii //weight: 1
        $x_1_3 = "so if you want your files dont be shy feel free to contact us and do an agreement on price" ascii //weight: 1
        $x_1_4 = "Delete you files if you dont need them" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_DO_2147765544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.DO!MTB"
        threat_id = "2147765544"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c vssadmin Delete Shadows /All /Quiet" ascii //weight: 1
        $x_1_2 = "How To Decrypt Files" ascii //weight: 1
        $x_1_3 = "@tuta.io" ascii //weight: 1
        $x_1_4 = "ALL YOUR FILES HAS BEEN ENCRYPTED" ascii //weight: 1
        $x_1_5 = "Don't find your backups? they have been Successfully encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Filecoder_DP_2147765549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.DP!MTB"
        threat_id = "2147765549"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\cryptopp800\\sha_simd.cpp" ascii //weight: 1
        $x_1_2 = "Salsa20" ascii //weight: 1
        $x_1_3 = "repter@tuta.io" ascii //weight: 1
        $x_1_4 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_5 = "CryptGenRandom" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_VKY_2147765802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.VKY!MSR"
        threat_id = "2147765802"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {51 ad 8b d0 0f ca b9 04 00 00 00 33 c0 0f a4 d0 06 d7 aa c1 c2 06 e2 f3 4e 59 e2 e4}  //weight: 1, accuracy: High
        $x_1_2 = {8b df b9 f4 00 00 00 89 4d d4 fc f3 a4 68 00 05 00 00 8d 45 d4 50 53 6a 00 6a 00 6a 00 ff 35 04 38 40 00 e8 11 05 00 00 83 c7 0c ff 4d cc 75 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_BB_2147768353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.BB!MTB"
        threat_id = "2147768353"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All your files are encrypted" ascii //weight: 1
        $x_1_2 = "bck 4.0 2020//11/6 fix 5.virus by znkzz" ascii //weight: 1
        $x_1_3 = "-LIBGCCW32-EH-SJLJ-GTHR-MINGW32" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_BB_2147768353_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.BB!MTB"
        threat_id = "2147768353"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "If You want decrypt files please contact us on jabber:" ascii //weight: 1
        $x_1_2 = "paymeplease@sj.ms" ascii //weight: 1
        $x_1_3 = "justfile.txt" ascii //weight: 1
        $x_1_4 = "INSTRUCTION.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_BB_2147768353_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.BB!MTB"
        threat_id = "2147768353"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "HOW_TO_RETURN_FILES.txt" ascii //weight: 1
        $x_1_2 = "wmic shadowcopy delete" ascii //weight: 1
        $x_1_3 = {74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 [0-5] 2e 65 78 65 20 2f 54 20 2f 46}  //weight: 1, accuracy: Low
        $x_1_4 = "don't have enough time to think each day payment will increase and after one week your key will be deleted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_DV_2147768400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.DV!MTB"
        threat_id = "2147768400"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Unable to perform military grade AES256 encryption for file !" ascii //weight: 1
        $x_1_2 = ".encCould not send packet to ." ascii //weight: 1
        $x_1_3 = "This program executes potentially dangreous operations" ascii //weight: 1
        $x_1_4 = "We're going to encrypt ALL THE THINGS. Type 'YES' to continue." ascii //weight: 1
        $x_1_5 = "uuuuuuuubtnufruuuuuuuuuuuuuuuuuu" ascii //weight: 1
        $x_1_6 = "Once instance has previously been poisoned" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Filecoder_DY_2147768545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.DY!MTB"
        threat_id = "2147768545"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Microsoft\\Windows\\SystemRestore\\SR\" /disable" ascii //weight: 1
        $x_1_2 = "/set {default} bootstatuspolicy ignoreallfailures" ascii //weight: 1
        $x_1_3 = "/set {default} recoveryenabled no" ascii //weight: 1
        $x_1_4 = "delete catalog -quiet" ascii //weight: 1
        $x_1_5 = "cipher.exe" ascii //weight: 1
        $x_1_6 = "ncryption" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_EA_2147769219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.EA!MTB"
        threat_id = "2147769219"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Encryption Completed !!!" ascii //weight: 1
        $x_1_2 = ".onion.pet/http/get.php" ascii //weight: 1
        $x_1_3 = "~Ransomware" ascii //weight: 1
        $x_1_4 = "cryptopp800" ascii //weight: 1
        $x_1_5 = "/v NoRunNowBackup  /t REG_DWORD /d 1 /f" ascii //weight: 1
        $x_1_6 = "/v DisableTaskMgr  /t REG_DWORD /d 0 /f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_DE_2147772039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.DE!MTB"
        threat_id = "2147772039"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HOW TO BACK YOUR FILES.exe" ascii //weight: 1
        $x_1_2 = "Hermes" ascii //weight: 1
        $x_1_3 = "Requirements.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_DF_2147772040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.DF!MTB"
        threat_id = "2147772040"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "__DECRYPT_NOTE__" ascii //weight: 1
        $x_1_2 = ".EXTEN" ascii //weight: 1
        $x_1_3 = "stopmarker" ascii //weight: 1
        $x_1_4 = "FindFirstFileExW" ascii //weight: 1
        $x_1_5 = "FindNextFileW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_FD_2147772217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.FD!MTB"
        threat_id = "2147772217"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "File has been encrypted using 256-bit Advanced Encryption Standard" ascii //weight: 1
        $x_1_2 = "unknowndll.pdb" ascii //weight: 1
        $x_1_3 = "FindFirstFileA" ascii //weight: 1
        $x_1_4 = "FindNextFileW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_FE_2147772218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.FE!MTB"
        threat_id = "2147772218"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "How To Decrypt Files" ascii //weight: 1
        $x_1_2 = "dontcryptanyway" ascii //weight: 1
        $x_1_3 = "helpmedecode@tutanota.com" ascii //weight: 1
        $x_1_4 = "decryptioner@airmail.cc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_SW_2147773051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.SW!MSR"
        threat_id = "2147773051"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "44"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tor browser" wide //weight: 1
        $x_1_2 = "cynet ransom protection(don't delete)" wide //weight: 1
        $x_10_3 = "EncryptDisk(%ws) DONE" ascii //weight: 10
        $x_10_4 = "Your network is penetrated" ascii //weight: 10
        $x_1_5 = "@protonmail.ch" ascii //weight: 1
        $x_10_6 = "mally@mailfence.com" ascii //weight: 10
        $x_1_7 = "fake.pdb" ascii //weight: 1
        $x_10_8 = "ransomware.exe" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_PAA_2147774153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.PAA!MTB"
        threat_id = "2147774153"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 75 14 8b 02 89 84 9d bc fb ff ff 8b 45 fc 25 ?? ?? ?? ?? 89 02 8b 94 9d bc fb ff ff 03 c2 25 ?? ?? ?? ?? 79 07 48 0d ?? ?? ?? ?? 40 8b 75 18 8a 94 85 bc fb ff ff 8a 04 31 32 c2 88 04 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_AA_2147774270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.AA!MTB"
        threat_id = "2147774270"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Run GlitchByte ransomware" ascii //weight: 2
        $x_2_2 = "bcdedit /set {default} recoveryenabled no" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_AA_2147774270_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.AA!MTB"
        threat_id = "2147774270"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wmic shadowcopy delete" wide //weight: 1
        $x_1_2 = "wbadmin delete backup" wide //weight: 1
        $x_1_3 = "wbadmin delete systemstatebackup -keepversions:0" wide //weight: 1
        $x_1_4 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" wide //weight: 1
        $x_1_5 = "wbadmin delete systemstatebackup" wide //weight: 1
        $x_1_6 = "/c \"vssadmin delete shadows /all /quiet\"" wide //weight: 1
        $x_1_7 = "/!clear_shadow" wide //weight: 1
        $x_1_8 = "/c \"timeout /t 5 /nobreak&del \"" wide //weight: 1
        $x_1_9 = "Encryption completed" wide //weight: 1
        $x_1_10 = "END OF WIPE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

rule Ransom_Win32_Filecoder_P_2147776847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.P!MSR"
        threat_id = "2147776847"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "New RansomCrypt from Humble User:%username% Key:||%randomletter%||" wide //weight: 2
        $x_2_2 = "Ooops! Your files was encrypted" wide //weight: 2
        $x_2_3 = "If you dont want to pay the ransom your files and MBR will be deleted" wide //weight: 2
        $x_2_4 = "Ooops! Your MBR was been rewritten" ascii //weight: 2
        $x_2_5 = "this ransomware dont encrypt your files, erases it" ascii //weight: 2
        $x_1_6 = "DiscordSendWebhook.exe" wide //weight: 1
        $x_1_7 = "/v \"Payload\" /t REG_SZ /d \"powershell.exe start -verb runas '\"%0\"' am_admin -WindowStyle hidden\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Filecoder_AC_2147787410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.AC!MTB"
        threat_id = "2147787410"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CryptEncrypt failed" ascii //weight: 1
        $x_1_2 = "Ransom\\Release\\Ransom.pdb" ascii //weight: 1
        $x_1_3 = "Walk directory crypt failed" ascii //weight: 1
        $x_1_4 = "init_crypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_AC_2147787410_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.AC!MTB"
        threat_id = "2147787410"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ALL YOUR FILES HAS BEEN ENCRYPTED" ascii //weight: 1
        $x_1_2 = "For unlock your files follow the instructions from the readme_for_unlock.txt" ascii //weight: 1
        $x_1_3 = "readme_for_unlock.txt" wide //weight: 1
        $x_1_4 = "/c vssadmin.exe delete shadows /all /quiet" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_AC_2147787410_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.AC!MTB"
        threat_id = "2147787410"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-autospreadifnoav=" wide //weight: 1
        $x_1_2 = "chacha failed, please run x64 version or restart" wide //weight: 1
        $x_10_3 = "disbaled network encrypting" wide //weight: 10
        $x_1_4 = "\\slconfig.txt" wide //weight: 1
        $x_10_5 = "Delete Shadows /All /Quiet" wide //weight: 10
        $x_10_6 = "\\programdata\\secles" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_OJD_2147798541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.OJD!MTB"
        threat_id = "2147798541"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1c 82 02 1c 8a 8b 82 0c 04 00 00 02 1c 82 8b 45 fc 0f b6 04 07 89 82 0c 04 00 00 8b 15 ?? ?? ?? ?? 8b 82 04 04 00 00 8b 8a 00 04 00 00 8b 04 82 03 04 8a 0f b6 c8 0f b6 c3 8b 0c 8a 8b 04 82 33 0c 82 33 8a 0c 04 00 00 89 8a 10 04 00 00 a1 ?? ?? ?? ?? 8b 4d fc 8a 80 10 04 00 00 88 01 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_RA_2147809022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.RA!MTB"
        threat_id = "2147809022"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//blockchain.info/" ascii //weight: 1
        $x_1_2 = "\\del.bat" ascii //weight: 1
        $x_1_3 = "18sHYU49vUFk6TN6G2Pj6DSCUzkbLvwJt" ascii //weight: 1
        $x_1_4 = "FILES_BACK.txt" ascii //weight: 1
        $x_1_5 = "your files has been encrypted" ascii //weight: 1
        $x_1_6 = "getreceivedbyaddress" ascii //weight: 1
        $x_1_7 = "GetAsyncKeyState" ascii //weight: 1
        $x_1_8 = "CallNextHookEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_GF_2147809034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.GF!MTB"
        threat_id = "2147809034"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " /deny *S-1-1-0:(OI)(CI)(DE,DC)" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "--AutoStart" ascii //weight: 1
        $x_1_4 = "CryptEncrypt" ascii //weight: 1
        $x_1_5 = "OpenServiceW" ascii //weight: 1
        $x_1_6 = "YctXT9bq" ascii //weight: 1
        $x_1_7 = "delself.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_DLK_2147809350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.DLK!MTB"
        threat_id = "2147809350"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 4a fe 0f b6 42 ff c1 e1 08 0b c8 0f b6 02 c1 e1 08 8d 52 04 0b c8 0f b6 42 fd c1 e1 08 0b c8 89 4c bc 5c 47 83 ff 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_GH_2147809857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.GH!MTB"
        threat_id = "2147809857"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VolatileAttribute" ascii //weight: 1
        $x_1_2 = "LoadFromStream" ascii //weight: 1
        $x_1_3 = "SaveToFile" ascii //weight: 1
        $x_1_4 = "Encrypt_8bit" ascii //weight: 1
        $x_1_5 = "Decrypt_Block" ascii //weight: 1
        $x_1_6 = "IBlockChainingModel [M" ascii //weight: 1
        $x_1_7 = "Password" ascii //weight: 1
        $x_1_8 = "Username" ascii //weight: 1
        $x_1_9 = "ShellExecuteW" ascii //weight: 1
        $x_1_10 = "IdCustomTCPServer" ascii //weight: 1
        $x_1_11 = "DCPtwofish_LB3Modified" ascii //weight: 1
        $x_1_12 = "!QUERY_CREDENTIALS_ATTRIBUTES_FN_WY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_GG_2147809858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.GG!MTB"
        threat_id = "2147809858"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Microsoft\\Windows\\Start Menu\\Programs\\Startup\\h.vbs" ascii //weight: 1
        $x_1_2 = "CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_3 = "eicar.com" ascii //weight: 1
        $x_1_4 = "userprofile" ascii //weight: 1
        $x_1_5 = "taskkill /f /IM explorer.exe" ascii //weight: 1
        $x_1_6 = "!P%@AP[4\\PZX54(P" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_RTR_2147810704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.RTR!MTB"
        threat_id = "2147810704"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 01 33 02 2b 02 03 02 89 06 83 c2 04 47 8b c7 2b 45 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_DEC_2147810717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.DEC!MTB"
        threat_id = "2147810717"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cryptmanager@protonmail.com" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "your files have been encrypted" ascii //weight: 1
        $x_1_4 = "Bitcoins" ascii //weight: 1
        $x_1_5 = "cmd.exe /c vssadmin delete shadows /all /quiet" ascii //weight: 1
        $x_1_6 = "ReadMe_Decryptor.txt" ascii //weight: 1
        $x_1_7 = "taskkill /f /im sqlserver.exe" ascii //weight: 1
        $x_1_8 = "cmd.exe /c wmic shadowcopy delete" ascii //weight: 1
        $x_1_9 = "CryptGenRandom" ascii //weight: 1
        $x_1_10 = "sc stop WinDefend" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_RTS_2147811086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.RTS!MTB"
        threat_id = "2147811086"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RestartByRestartManager" ascii //weight: 1
        $x_1_2 = "All of your files have been encrypted" ascii //weight: 1
        $x_1_3 = "Your computer was infected  with a ransomware virus" ascii //weight: 1
        $x_1_4 = "Your files have been encrypted" ascii //weight: 1
        $x_1_5 = "Bitcoin" ascii //weight: 1
        $x_1_6 = "Coinmama" ascii //weight: 1
        $x_1_7 = "Bitpanda" ascii //weight: 1
        $x_1_8 = "How to restore your file" ascii //weight: 1
        $x_1_9 = "Cobra" ascii //weight: 1
        $x_1_10 = "Contacts Email:" ascii //weight: 1
        $x_1_11 = "UnhookWindowsHookEx" ascii //weight: 1
        $x_1_12 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_13 = "tbirdconfig" ascii //weight: 1
        $x_1_14 = "sqbcoreservice" ascii //weight: 1
        $x_1_15 = "KillTimer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_AF_2147816437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.AF!MTB"
        threat_id = "2147816437"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\zzz\\crypt\\crypt5.vbp" wide //weight: 1
        $x_1_2 = "TASKKILL /IM 1cv8.exe /F" wide //weight: 1
        $x_1_3 = "TASKKILL /IM winword.exe /F" wide //weight: 1
        $x_1_4 = "TASKKILL /IM excel.exe /F" wide //weight: 1
        $x_1_5 = "TASKKILL /IM powerpnt.exe /F" wide //weight: 1
        $x_1_6 = "TASKKILL /IM vmware.exe /F" wide //weight: 1
        $x_1_7 = "TASKKILL /IM VirtualBox.exe /F" wide //weight: 1
        $x_1_8 = "Desktop\\key1.txt" wide //weight: 1
        $x_1_9 = "c:\\1\\1.bmp" wide //weight: 1
        $x_1_10 = "Desktop\\INSTRUCTIONS.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_WTY_2147817052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.WTY!MTB"
        threat_id = "2147817052"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 fc 17 00 00 00 8b 55 08 83 c2 38 89 95 1c ff ff ff c7 85 14 ff ff ff 08 40 00 00 6a 08 8d 85 14 ff ff ff 50 8d 8d 64 ff ff ff 51}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_PAC_2147819911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.PAC!MTB"
        threat_id = "2147819911"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c8 8d 04 3b 33 c8 31 4d fc 8b 45 fc 01 05 ec 14 53 00 2b 75 fc 83 0d f4 14 53 00 ff 8b ce c1 e1 ?? 03 4d e8 8b c6 c1 e8 ?? 03 45 e0 8d 14 33 33 ca 33 c8 2b f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_MA_2147830298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.MA!MTB"
        threat_id = "2147830298"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c6 99 f7 f9 8a 44 15 ec 30 04 1e 46 3b f7 7c ef}  //weight: 1, accuracy: High
        $x_1_2 = "output.txt" ascii //weight: 1
        $x_1_3 = "DecryptMessage" ascii //weight: 1
        $x_1_4 = ":\\Windows\\Temp\\desktop.jpg" ascii //weight: 1
        $x_1_5 = "fuckme" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_MA_2147830298_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.MA!MTB"
        threat_id = "2147830298"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 33 89 7b 04 c6 05 59 50 4f 00 01 8b 45 08 50 8b 45 0c 50 53 b8 5c 9d 40 00 50 8b 45 f8 50 8b 45 fc 50 e8 e5 b3 ff ff}  //weight: 2, accuracy: High
        $x_1_2 = {54 61 69 6c 50 72 6f 63 65 73 73 69 6e 67 41 6e 64 4b 65 79 47 65 6e 09 53 69 6d 70 6c 65 52 53 41}  //weight: 1, accuracy: High
        $x_1_3 = {4f 6e 65 50 61 74 68 45 6e 63 72 79 70 74 69 6f 6e 09 4c 61 6e 54 68 72 65 61 64 0b 4c 6f 63 61 6c 54 68 72 65 61 64 0d}  //weight: 1, accuracy: High
        $x_1_4 = "FileEncryption" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_PT_2147832024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.PT!MTB"
        threat_id = "2147832024"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f4 0f b6 00 83 f0 15 89 c2 8b 45 f4 88 10 83 45 f4 01 83 45 f0 01 8b 45 f0 3b 45 e4 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_RN_2147834018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.RN!MTB"
        threat_id = "2147834018"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {23 e1 ba 8a 1a e0 f4 b0 bd 09 94 88 7c 97 d4 c9 e3 e5 ff 71 4d 52 5e bc 70 e5 12 de 21 7d d8 86 d4 73 98 ed 92 be 5b 1d b9 e2 30 2f 3b a4 4c 75 da 1d 4d 33 3b ed 90 26 64 ad 4c 73 87 d4 0f 9a ed 8e 1a 79 b4 3b 8a 79 2e 56 91 22 c7 41 04 ea 0f 31 8d 50 81 c8 19 f4 9c 08 ab cd a6 1a 2b 8b f0 62 ee dc 1f 55 ae 41 fa 73 d7 8e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_MB_2147894350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.MB!MTB"
        threat_id = "2147894350"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "owlsupport@decoymail.com" wide //weight: 5
        $x_5_2 = "owladmin@onionmail.org" wide //weight: 5
        $x_1_3 = "_lock_file" ascii //weight: 1
        $x_1_4 = "_Lockit" ascii //weight: 1
        $x_1_5 = "start info.txt" ascii //weight: 1
        $x_1_6 = "info.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_MB_2147894350_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.MB!MTB"
        threat_id = "2147894350"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "ransomware001.pdb" ascii //weight: 5
        $x_1_2 = "<target directory> [/v] [/s] [/o] [/a] [/r] [-c <number>] [-d <second>]" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "ransomware" ascii //weight: 1
        $x_1_5 = "v = verbose, print all logs for debugging" ascii //weight: 1
        $x_1_6 = "r = registry, add the program to the Windows start-up" ascii //weight: 1
        $x_1_7 = "continuous number of files to be encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_PABS_2147897555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.PABS!MTB"
        threat_id = "2147897555"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 03 8b ca c1 e9 18 33 c8 c1 e2 08 0f b6 c1 33 14 85 ?? ?? ?? ?? 43 83 ee 01 75 e3}  //weight: 1, accuracy: Low
        $x_1_2 = "select * from Win32_ShadowCopy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_PACH_2147897878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.PACH!MTB"
        threat_id = "2147897878"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 e2 51 2e 00 00 0f b6 95 f8 fd ff ff 0f b7 85 c8 fc ff ff 0f b6 8d 98 fe ff ff 8d 04 01 81 e2 75 1c 00 00 35 85 0f 00 00 8d 04 00 8d 14 02 13 95 a0 fe ff ff 0f b6 85 60 ff ff ff 3b 85 d4 fd ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_PACP_2147898800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.PACP!MTB"
        threat_id = "2147898800"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 55 f4 83 c2 01 89 55 f4 81 7d f4 8c 00 00 00 73 16 8b 45 d4 03 45 f4 0f b6 08 33 4d c8 8b 55 d4 03 55 f4 88 0a eb d8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_PACI_2147901395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.PACI!MTB"
        threat_id = "2147901395"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {51 52 8b 54 24 0c 8b 4c 24 08 81 c1 ff 00 00 00 29 d1 41 41 89 4c 24 08 5a 59 c2 04 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_PADF_2147901853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.PADF!MTB"
        threat_id = "2147901853"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 03 32 06 46 4f 75 0a be ?? ?? ?? ?? bf 09 00 00 00 88 03 83 f9 00 74 04 4b 49 eb e3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_NBA_2147905566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.NBA!ibt"
        threat_id = "2147905566"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Function detected: %s:%s" ascii //weight: 1
        $x_1_2 = "expand 32-byte k" ascii //weight: 1
        $x_1_3 = "__DECRYPT_NOTE__" ascii //weight: 1
        $x_1_4 = "NBA_LOG.txt" ascii //weight: 1
        $x_1_5 = "Unhook module: %ntdll.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_PADV_2147910143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.PADV!MTB"
        threat_id = "2147910143"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NanoLocker" ascii //weight: 1
        $x_1_2 = "We recommend to you turn off or disable all antivirus and use your computer only for sending money until decryption does not complete" ascii //weight: 1
        $x_1_3 = "Using any third-party Cryptor, Antimalware or AntiLocker can destroy this Decryptor and LOSE ALL YOUR DATA FOREVER" ascii //weight: 1
        $x_1_4 = "ransomware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_PAEB_2147911420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.PAEB!MTB"
        threat_id = "2147911420"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 45 0c 8b 4d 08 ba b7 bc 00 00 c7 44 24 28 24 4d 00 00 be 24 4d 00 00 c7 44 24 20 13 78 00 00 bf 13 78 00 00 c7 44 24 34 00 00 00 00 c7 44 24 30 38 2a 00 00 8b 5c 24 28 88 44 24 13 89 f0 35 87 59 00 00 89 44 24 2c 29 da 39 fa 89 74 24 0c 89 4c 24 08 76}  //weight: 2, accuracy: High
        $x_2_2 = {35 c9 70 fe 5a be c9 43 00 00 89 44 24 34 89 f8 89 54 24 30 f7 e6 8b 74 24 48 69 f6 c9 43 00 00 01 f2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_PAEG_2147912527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.PAEG!MTB"
        threat_id = "2147912527"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 10 8b 55 f4 32 04 32 8b 55 e0 88 02 42 8b 45 f4 40 89 55 e0 89 45 f4 3b c7 72 da}  //weight: 1, accuracy: High
        $x_1_2 = "select * from Win32_ShadowCopy" wide //weight: 1
        $x_1_3 = "ROOT\\cimv2" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_PAEL_2147912753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.PAEL!MTB"
        threat_id = "2147912753"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b cd 0f b6 44 0c 24 32 04 33 8b 4c 24 1c 88 06 b8 4f ec c4 4e 8d 0c 31 f7 e1 8b cf c1 ea 03 6b c2 1a 2b c8 2b cd}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 44 0c 27 8b 4c 24 50 32 44 31 fc 88 46 ff 81 ff 00 86 02 00 0f 82 55}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_ARA_2147919170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.ARA!MTB"
        threat_id = "2147919170"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b ce 8b 55 ?? 83 e1 07 c1 e1 03 e8 ?? ?? ?? ?? 8b 4d 08 30 04 0e 83 c6 01 83 d3 00 3b 5d}  //weight: 2, accuracy: Low
        $x_2_2 = {8a 44 0d ec 88 81 ?? ?? ?? ?? 83 c1 01 83 d2 00 75 07 83 f9 0e 72 e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_SUR_2147922721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.SUR!MTB"
        threat_id = "2147922721"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "KILL_APPS_ENCRYPT_AGAIN" ascii //weight: 2
        $x_2_2 = "8C8B8F8F-C273-40D5-8A0E-07CE39BFA8BB" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_SUR_2147922721_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.SUR!MTB"
        threat_id = "2147922721"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Your files have been encrypted!" ascii //weight: 2
        $x_2_2 = "look at any file with .raz extension" ascii //weight: 2
        $x_1_3 = "AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_PAFR_2147922991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.PAFR!MTB"
        threat_id = "2147922991"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b ce 8b 55 ?? 83 e1 07 c1 e1 03 e8 ?? ?? ?? ?? 8b 4d ?? 30 04 0e 83 c6 01 83 d3 00 3b 5d ?? 72 ?? 77 ?? 3b f7 72}  //weight: 2, accuracy: Low
        $x_2_2 = {99 b9 34 00 00 00 f7 f9 b8 41 00 00 00 b9 47 00 00 00 80 fa 1a 0f 4d c1 02 c2 8b e5 5d c3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_SWA_2147931284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.SWA!MTB"
        threat_id = "2147931284"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/c vssadmin.exe delete shadows /all /quiet" wide //weight: 2
        $x_2_2 = "How To Restore Your Files.txt" wide //weight: 2
        $x_1_3 = "DoYouWantToHaveSexWithCuongDong" ascii //weight: 1
        $x_1_4 = "processes killer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Filecoder_NMA_2147935908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.NMA!MTB"
        threat_id = "2147935908"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff d0 83 ec 14 85 c0 0f 85 ?? ?? 00 00 8b 45 f4 8d 55 88 89 54 24 14 8d 55 8c 89 54 24 10}  //weight: 2, accuracy: Low
        $x_1_2 = "somesomeWar_EOF" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_PAGQ_2147938531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.PAGQ!MTB"
        threat_id = "2147938531"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "cmd /c \"vssadmin Delete Shadows /All /Quiet\"" ascii //weight: 2
        $x_2_2 = "cmd /c \"bcdedit /set {default} bootstatuspolicy ignoreallfailures\"" ascii //weight: 2
        $x_1_3 = "cmd /c \"taskkill /F /IM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_PAGR_2147938532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.PAGR!MTB"
        threat_id = "2147938532"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "You are hit with a virus." wide //weight: 2
        $x_2_2 = "Your key files are locked." wide //weight: 2
        $x_1_3 = "Upon payment, your key will be dispatched to you at" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_PAGS_2147939254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.PAGS!MTB"
        threat_id = "2147939254"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "LOCKIFY R1 RANSOMEWARE!" ascii //weight: 3
        $x_2_2 = "All your personal informations, datas, Files, Documents, Pictures, Logins, Videos etc.. all were completely ENCRYPTED" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_PAQD_2147939604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.PAQD!MTB"
        threat_id = "2147939604"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 45 f4 c1 e0 08 89 c2 8b 45 f0 01 d0 8b 14 85 ?? ?? ?? ?? 8b 45 14 8b 4d f4 89 cb c1 e3 08 8b 4d f0 01 d9 89 14 88 83 45 f0 01 81 7d f0 ff}  //weight: 3, accuracy: Low
        $x_2_2 = {8b 45 f4 ba 00 00 00 00 f7 75 f0 89 d0 8b 44 85 b4 31 c1 8b 45 14 8b 55 f4 81 c2 00 04 00 00 89 0c 90 83 45 f4 01 83 7d f4 11}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_PAGT_2147939857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.PAGT!MTB"
        threat_id = "2147939857"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "/c vssadmin.exe delete shadows /all /quiet" wide //weight: 3
        $x_2_2 = "worth of bitcoin to wallet:" wide //weight: 2
        $x_2_3 = "ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 1 /f" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_PAGV_2147939858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.PAGV!MTB"
        threat_id = "2147939858"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c7 00 5c 72 65 63 c7 40 04 6f 76 65 72 c7 40 06 65 72 79 2e c7 40 0a 65 78 65 00 c7 44 24 08 00 00 00 00 8d 85 f0 fd ff ff 89 44 24 04 8d 85 f4 fe ff ff 89 04 24 a1}  //weight: 2, accuracy: High
        $x_1_2 = {8b 45 f4 ba 00 00 00 00 f7 75 f0 89 d0 8b 44 85 b4 31 c1 8b 45 14 8b 55 f4 81 c2 00 04 00 00 89 0c 90 83 45 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_PAGW_2147940067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.PAGW!MTB"
        threat_id = "2147940067"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0f b6 54 04 ?? 31 d1 88 4c 04 ?? 40 83 f8 ?? 7d 09 0f b6 4c 04 ?? 72 e8}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_PAGW_2147940067_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.PAGW!MTB"
        threat_id = "2147940067"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Desktop wallpaper changed successfully." ascii //weight: 2
        $x_1_2 = "Failed to create flash window. Error code:" ascii //weight: 1
        $x_1_3 = "Screen flash complete." ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_2_5 = "Failed to set autostart registry value. Error code:" ascii //weight: 2
        $x_2_6 = "%s.enc" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_PAGX_2147940068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.PAGX!MTB"
        threat_id = "2147940068"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "d21pYyBTSEFET1dDT1BZIERFTEVURTsKdnNzYWRtaW4gRGVsZXRlIFNoYWRvd3MgL" ascii //weight: 2
        $x_2_2 = "SGVsbG8sIAp5b3VyIGZpbGVzIGhhdmUgYmVlbiBlbmNyeXB0ZWQhIFRvIHJldHVyb" ascii //weight: 2
        $x_1_3 = "IGNhbGwgdGVybWluYXRlOwpiY2RlZGl0IC9zZXQge2RlZmF1bHR9IHJlY292ZXJ5Z" ascii //weight: 1
        $x_1_4 = "W5hYmxlZCBObzsKYmNkZWRpdCAvc2V0IHtkZWZhdWx0fSBib290c3RhdHVzcG9saW" ascii //weight: 1
        $x_1_5 = "N5IGlnbm9yZWFsbGZhaWx1cmVzOw==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_QL_2147940695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.QL!MTB"
        threat_id = "2147940695"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "C:\\nodecryptor.txt" ascii //weight: 2
        $x_2_2 = "All your important files have been encrypted! Your data is locked." ascii //weight: 2
        $x_2_3 = "YOU CAN NOT RECOVER YOUR FILES" ascii //weight: 2
        $x_2_4 = "INFECTED BY NODECRYPT" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_PAHH_2147946170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.PAHH!MTB"
        threat_id = "2147946170"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "SGVsbG8sIGFsbCB5b3VyIGZpbGVzIGhhdmUgYmVlbiBvdmVyd3JpdHRlbi4gU2VuZCAxMDAkIHRvIHRoaXMgYnRjIGFkZHJlc3MgMUNLOENTWU1NbVM3OUdXOHJtNndQUVJZczdlSGhSdlpINCB0byByZWNvdmVyIGl0Lg==" ascii //weight: 5
        $x_1_2 = "\\Desktop\\readme.txt" ascii //weight: 1
        $x_1_3 = "USERPROFILE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_PAHK_2147946769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.PAHK!MTB"
        threat_id = "2147946769"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SANDBOX_MODE" wide //weight: 1
        $x_2_2 = "read_it.txt" wide //weight: 2
        $x_1_3 = "Your files have been encrypted" wide //weight: 1
        $x_2_4 = "Local\\CHAOS_RUNNING" wide //weight: 2
        $x_2_5 = "MALWARE" wide //weight: 2
        $x_1_6 = "virus" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Filecoder_MSD_2147947396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Filecoder.MSD!MTB"
        threat_id = "2147947396"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {32 04 37 32 44 24 ?? 8b 4c 24 10 88 04 31 8b 03 89 44 24 10 8a 04 30 46 88 44 24 0f 8b 44 24 14 8b 38 8b 40 04 2b c7 3b f0 72}  //weight: 5, accuracy: Low
        $x_1_2 = ".encrypted" ascii //weight: 1
        $x_1_3 = ".locked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

