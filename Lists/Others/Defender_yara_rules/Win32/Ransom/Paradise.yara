rule Ransom_Win32_Paradise_R_2147727633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Paradise.R"
        threat_id = "2147727633"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Paradise"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "To decrypt your files, please contact us by mail" ascii //weight: 1
        $x_1_2 = "/c vssadmin delete shadows /all /quiet" ascii //weight: 1
        $x_1_3 = "paradise_key_pub.bin" ascii //weight: 1
        $x_1_4 = "with respect Ransomware Paradise Team" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Paradise_A_2147744611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Paradise.A!MSR"
        threat_id = "2147744611"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Paradise"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your important files produced on this computer have been encrypted due a security problem" ascii //weight: 1
        $x_1_2 = "Do not attempt to use the antivirus or uninstall the program" ascii //weight: 1
        $x_1_3 = "---==%$$$OPEN_ME_UP$$$==---.txt" wide //weight: 1
        $x_1_4 = "delete shadows /all /quiet" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Paradise_PA_2147745500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Paradise.PA!MTB"
        threat_id = "2147745500"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Paradise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EncryptFolder" ascii //weight: 1
        $x_1_2 = "EncryptFile" ascii //weight: 1
        $x_1_3 = "DeleteShadowCopies" ascii //weight: 1
        $x_1_4 = "CycleDefender" ascii //weight: 1
        $x_1_5 = "RSA_MasterPublic" ascii //weight: 1
        $x_1_6 = "CryptedExtension" ascii //weight: 1
        $x_1_7 = "DecryptNoteFilename" ascii //weight: 1
        $x_1_8 = "ID_of_client" wide //weight: 1
        $x_1_9 = "/C sc delete VSS" wide //weight: 1
        $x_1_10 = "_WHERE_MY_FILES_=#.html" wide //weight: 1
        $x_1_11 = "@helprestore" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Paradise_PA_2147745500_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Paradise.PA!MTB"
        threat_id = "2147745500"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Paradise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\sysnative\\vssadmin.exe" wide //weight: 1
        $x_1_2 = "delete shadows /all /quiet" wide //weight: 1
        $x_1_3 = "%SOFTWARE\\Policies\\Microsoft\\Windows Defender" wide //weight: 1
        $x_1_4 = "DisableAntiSpyware" wide //weight: 1
        $x_1_5 = "All your files have been blocked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Paradise_BB_2147763777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Paradise.BB!MTB"
        threat_id = "2147763777"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Paradise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "delete shadows /all /quiet" wide //weight: 10
        $x_1_2 = "C:\\Windows\\sysnative\\vssadmin.exe" wide //weight: 1
        $x_2_3 = "/c netsh advfirewall set allprofiles state off" wide //weight: 2
        $x_2_4 = "/c bcdedit /set {current} bootstatuspolicy ignoreallfailures" wide //weight: 2
        $x_2_5 = "/c bcdedit /set {current} recoveryenabled no" wide //weight: 2
        $x_2_6 = "/c timeout 1 && del \"%s\" >> NUL" wide //weight: 2
        $x_10_7 = "All your files have been ENCRYPTED!!!" ascii //weight: 10
        $x_1_8 = "tell your unique ID" ascii //weight: 1
        $x_1_9 = ".bigbosshorse" ascii //weight: 1
        $x_2_10 = "#Decryption#.txt" ascii //weight: 2
        $x_5_11 = "%appdata%\\_uninstalling_.png" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Paradise_BC_2147763778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Paradise.BC!MTB"
        threat_id = "2147763778"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Paradise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Do not try to decrypt" ascii //weight: 1
        $x_1_2 = "DisableAntiSpyware" ascii //weight: 1
        $x_1_3 = "delete shadows /all /quiet" ascii //weight: 1
        $x_1_4 = "Do not rename encrypted files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Paradise_BD_2147763779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Paradise.BD!MTB"
        threat_id = "2147763779"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Paradise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "/C sc delete VSSA" ascii //weight: 10
        $x_10_2 = "You have to pay in Bitcoins." ascii //weight: 10
        $x_5_3 = {52 45 41 44 4d 45 [0-10] 68 74 6d 6c}  //weight: 5, accuracy: Low
        $x_1_4 = "CycleDefender" ascii //weight: 1
        $x_1_5 = "DeleteShadowCopies" ascii //weight: 1
        $x_1_6 = "CryptedPrivateKey" ascii //weight: 1
        $x_1_7 = "System.Security.Cryptography" ascii //weight: 1
        $x_1_8 = "RSACryptoServiceProvider" ascii //weight: 1
        $x_1_9 = "<CRYPTED>" ascii //weight: 1
        $x_1_10 = "</CRYPTED>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Paradise_BG_2147763961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Paradise.BG!MTB"
        threat_id = "2147763961"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Paradise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Do not rename encrypted files" ascii //weight: 1
        $x_1_2 = "WHAT HAPPENED!" ascii //weight: 1
        $x_1_3 = "taridd" wide //weight: 1
        $x_10_4 = "Files on your pc were encoded" ascii //weight: 10
        $x_1_5 = "OPEN_ME_UP" wide //weight: 1
        $x_10_6 = "DisableAntiSpyware" wide //weight: 10
        $x_10_7 = "delete shadows /all /quiet" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Paradise_BI_2147766270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Paradise.BI!MTB"
        threat_id = "2147766270"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Paradise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 db 33 c9 33 d2 33 f6 33 ff ff d0 [0-96] 33 db 33 c9 33 d2 33 f6 33 ff ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {0f 45 d0 8b 4d d8 8b 45 b0 88 14 01 83 3d 98 37 42 00 00 75 43}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Paradise_BA_2147766632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Paradise.BA!MTB"
        threat_id = "2147766632"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Paradise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Paradise v1.00" ascii //weight: 1
        $x_1_2 = {56 69 72 75 73 20 73 69 7a 65 [0-32] 62 79 74 65 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Paradise_BN_2147768912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Paradise.BN!MTB"
        threat_id = "2147768912"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Paradise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "postg" ascii //weight: 1
        $x_1_2 = "store.exe" ascii //weight: 1
        $x_1_3 = "bes10" ascii //weight: 1
        $x_1_4 = "taridd" ascii //weight: 1
        $x_1_5 = "ping 127.0.0.1 && del \"%s\"" ascii //weight: 1
        $x_1_6 = "http://prt-recovery.support/chat/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

