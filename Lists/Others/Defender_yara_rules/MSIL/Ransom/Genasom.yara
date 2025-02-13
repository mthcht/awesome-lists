rule Ransom_MSIL_Genasom_G_2147682011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Genasom.G"
        threat_id = "2147682011"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "warnings before your system becomes unusable !" wide //weight: 1
        $x_1_2 = "complete a survey in order to unlock your computer." wide //weight: 1
        $x_1_3 = "as before when you unlock your PC." wide //weight: 1
        $x_1_4 = {5c 00 74 00 6d 00 70 00 [0-12] 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00}  //weight: 1, accuracy: Low
        $x_1_5 = {55 00 6e 00 6c 00 6f 00 63 00 6b 00 20 00 63 00 6f 00 64 00 65 00 3a 00 ?? ?? 70 00 6e 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_6 = "firewall set opmode disable" wide //weight: 1
        $x_1_7 = "-s -f -t 0" wide //weight: 1
        $x_1_8 = "taskmgr.cmd.msconfig." wide //weight: 1
        $x_1_9 = "%selfdestruct%" wide //weight: 1
        $x_1_10 = "%lockmousepos%" wide //weight: 1
        $x_1_11 = "%swapmouse%" wide //weight: 1
        $x_1_12 = "%hidetaskbar%" wide //weight: 1
        $x_1_13 = "utilman.exe" wide //weight: 1
        $x_1_14 = {0a 20 19 03 00 00 02 28 ?? 00 00 0a 20 00 00 08 00 28 ?? 00 00 0a 28 21 00 00 06 26 de 03 26 de 00 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Ransom_MSIL_Genasom_H_2147682846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Genasom.H"
        threat_id = "2147682846"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "warnings before your system becomes unuseable." wide //weight: 1
        $x_1_2 = "This is warning number" wide //weight: 1
        $x_1_3 = "Survey says..." wide //weight: 1
        $x_1_4 = "Unlock code:" wide //weight: 1
        $x_1_5 = "shutdown -s -t 0" wide //weight: 1
        $x_1_6 = "btnValidate" wide //weight: 1
        $x_1_7 = "trololololololololololo.com" wide //weight: 1
        $x_1_8 = ".youporn.com" wide //weight: 1
        $x_1_9 = ".loltrain.com" wide //weight: 1
        $x_1_10 = {74 00 61 00 73 00 6b 00 6d 00 67 00 72 00 ?? ?? 63 00 6d 00 64 00 ?? ?? 6d 00 73 00 63 00 6f 00 6e 00 66 00 69 00 67 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Genasom_I_2147683598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Genasom.I"
        threat_id = "2147683598"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\seo\\Sdchost.exe" wide //weight: 1
        $x_1_2 = "FileiceRansomware" wide //weight: 1
        $x_1_3 = "DisableChangePassword" wide //weight: 1
        $x_1_4 = "Unlock Your PC" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Genasom_L_2147685479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Genasom.L"
        threat_id = "2147685479"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Unlock Code:" wide //weight: 1
        $x_1_2 = "Your Computer is Locked" wide //weight: 1
        $x_1_3 = "You must first complete the survey in order to get your unlock password." wide //weight: 1
        $x_1_4 = "Kill Gen:" wide //weight: 1
        $x_1_5 = "Kill Def:" wide //weight: 1
        $x_1_6 = "Start-Up Name:" wide //weight: 1
        $x_1_7 = "explorer.exe /n /e c:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Ransom_MSIL_Genasom_M_2147686026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Genasom.M"
        threat_id = "2147686026"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "REG add HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\System /v DisableCMD /t REG_DWORD /d 1 /f" wide //weight: 1
        $x_1_2 = "Verify your version of Microsoft Windows" wide //weight: 1
        $x_1_3 = "New Product Key:" wide //weight: 1
        $x_1_4 = "DisableSR" wide //weight: 1
        $x_1_5 = "DisableRegistryTools" wide //weight: 1
        $x_1_6 = "DisableTaskMgr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Genasom_P_2147695643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Genasom.P"
        threat_id = "2147695643"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {75 00 70 00 64 00 61 00 74 00 65 00 2e 00 65 00 78 00 65 00 90 00 02 00 08 00 74 00 6f 00 72 00 2e 00 65 00 78 00 65 00 90 00 02 00 08 00 72 00 75 00 6e 00 57 00 49 00 4e 00 2e 00 65 00 78 00 65 00 90 00 02 00 08 00 55 00 70 00 64 00 61 00 74 00 65 00 4c 00 6f 00 61 00 64 00 65 00 72 00 2e 00 65 00 78 00 65 00}  //weight: 8, accuracy: High
        $x_8_2 = {67 65 74 5f 44 65 63 72 79 70 74 00 67 65 74 5f 49 63 6f 6e 43 72 79 00 67 65 74 5f 74 69 6b 65 74 00 45 6e 63 72 79 70 74}  //weight: 8, accuracy: High
        $x_4_3 = {49 00 63 00 6f 00 6e 00 43 00 72 00 79 00 2e 00 69 00 63 00 6f 00 90 00 02 00 08 00 74 00 69 00 6b 00 65 00 74 00 2e 00 65 00 78 00 65 00 90 00 02 00 08 00 42 00 6c 00 6f 00 63 00 6b 00 65 00 64 00}  //weight: 4, accuracy: High
        $x_4_4 = "regKay.SetValue(\"DeleteALLocker\"" wide //weight: 4
        $x_2_5 = {44 6f 77 6e 6c 6f 61 64 00 45 6d 65 72 67 65 6e 63 79 44 65 6c 65 74 65}  //weight: 2, accuracy: High
        $x_2_6 = {65 78 65 4e 61 6d 65 00 4c 6f 63 6b 65 72}  //weight: 2, accuracy: High
        $x_2_7 = {50 61 79 6d 65 6e 74 53 45 54 00 50 72 6f 66 69 6c 65 49 6e 66 6f}  //weight: 2, accuracy: High
        $x_2_8 = {53 79 73 74 65 6d 41 75 74 6f 72 75 6e 00 55 70 64 61 74 65 4c 6f 61 64 65 72}  //weight: 2, accuracy: High
        $x_2_9 = {45 6e 67 69 6e 65 00 6c 6f 61 64 65 72 00 6c 6f 63 6b 65 72 78 30 30 74 6f 72}  //weight: 2, accuracy: High
        $x_2_10 = {54 69 6b 65 74 48 65 6c 70 65 72 00 67 65 74 5f 53 79 73 74 65 6d 41 75 74 6f 72 75 6e}  //weight: 2, accuracy: High
        $x_1_11 = "TiketHelper.dll" wide //weight: 1
        $x_1_12 = "Mail.RU NewGamesT\\" wide //weight: 1
        $x_1_13 = {49 53 68 65 6c 6c 4c 69 6e 6b 57 00 73 68 6c 5f 6c 69 6e 6b 00 53 68 6f 72 74 43 75 74}  //weight: 1, accuracy: High
        $x_1_14 = {48 69 64 64 65 6e 46 69 6c 65 00 53 74 61 72 74 41 50 50}  //weight: 1, accuracy: High
        $x_1_15 = {73 65 74 5f 73 65 73 73 69 6f 6e 00 67 65 74 5f 50 61 79 61 62 6c 65 53 74 72 69 6e 67}  //weight: 1, accuracy: High
        $x_1_16 = "<payment>k__BackingField" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 6 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_4_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_4_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 5 of ($x_2_*))) or
            ((1 of ($x_8_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_8_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_8_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*) and 5 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*) and 6 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_8_*) and 2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*) and 2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((2 of ($x_8_*) and 2 of ($x_1_*))) or
            ((2 of ($x_8_*) and 1 of ($x_2_*))) or
            ((2 of ($x_8_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Genasom_2147729286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Genasom!MTB"
        threat_id = "2147729286"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Genasom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ransom.BL" ascii //weight: 1
        $x_1_2 = "Ransom.PL" ascii //weight: 1
        $x_2_3 = "your files have been encrypted" wide //weight: 2
        $x_2_4 = "Ransomware.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Genasom_R_2147731305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Genasom.R"
        threat_id = "2147731305"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fuckDirectory" ascii //weight: 1
        $x_1_2 = "\\@READ_IT@.txt" wide //weight: 1
        $x_1_3 = "All your files were fucked forever by FileFuck! You can not stop us, you idiot" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Genasom_R_2147731305_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Genasom.R"
        threat_id = "2147731305"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ransomware_sample" ascii //weight: 1
        $x_1_2 = "All your files belong to me! Pay the ransom if you want them back.[HP INTERNAL USE ONLY]" wide //weight: 1
        $x_1_3 = {5c 72 61 6e 73 6f 6d 77 61 72 65 5f 73 61 6d 70 6c 65 5c 6f 62 6a 5c [0-16] 5c 72 61 6e 73 6f 6d 77 61 72 65 5f 73 61 6d 70 6c 65 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Genasom_Q_2147743460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Genasom.Q"
        threat_id = "2147743460"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Genasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "encrypted your data" ascii //weight: 1
        $x_1_2 = "BTC payment" ascii //weight: 1
        $x_1_3 = "CyberSecurityIsABitch" wide //weight: 1
        $x_1_4 = "ShortCutVBS.vbs" wide //weight: 1
        $x_1_5 = "Your Data Has Been Encrypted" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_MSIL_Genasom_TA_2147744945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Genasom.TA!MSR"
        threat_id = "2147744945"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Genasom"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "C:\\Users\\ElPro\\source\\repos\\ransom\\ransom\\obj\\Debug\\ransom.pdb" ascii //weight: 4
        $x_1_2 = "ransom.Resources" wide //weight: 1
        $x_1_3 = "Decrypting files" wide //weight: 1
        $x_1_4 = "YOUR HARDDISKS HAVE BEEN ENCRYPTED" wide //weight: 1
        $x_1_5 = "http://b2xhIG0zbiB4ZA.onion" ascii //weight: 1
        $x_1_6 = "http://4kx812nk2SZ93cKz290.onion" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Genasom_BS_2147745825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Genasom.BS!MTB"
        threat_id = "2147745825"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Genasom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c vssadmin.exe delete shadows /all /quiet" wide //weight: 1
        $x_1_2 = "All your data has been locked us. You want to return? Contact to Email: Unlockme501@protonmail.ch" wide //weight: 1
        $x_1_3 = "C:\\Users\\mvj\\Music\\mehdi ransomware\\mehdi update" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Genasom_R_2147745829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Genasom.R!MSR"
        threat_id = "2147745829"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Genasom"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Ransom\\Exe\\Statik Version\\CrypterLastVersion\\CrypterLastVersion\\obj\\Release\\JavaEmbededLibrary.pdb" ascii //weight: 3
        $x_1_2 = "SELECT * FROM Win32_DeviceChangeEvent WHERE EventType = 2" wide //weight: 1
        $x_1_3 = ".ciphered" wide //weight: 1
        $x_1_4 = "ENCRYPTED" wide //weight: 1
        $x_1_5 = "CreateEncryptor" ascii //weight: 1
        $x_1_6 = "UnauthorizedAccess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

