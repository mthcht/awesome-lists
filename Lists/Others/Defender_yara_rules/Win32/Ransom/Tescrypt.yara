rule Ransom_Win32_Tescrypt_A_2147692253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tescrypt.A"
        threat_id = "2147692253"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tescrypt"
        severity = "7"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All of your files were protected by a strong encryption with RSA-2048" ascii //weight: 1
        $x_1_2 = "Decrypting of YOUR FILES is only possible with the help of the private key and decrypt program, which is on our SECRET SERVER!!!." ascii //weight: 1
        $x_1_3 = "delete shadows /all" ascii //weight: 1
        $x_1_4 = "\\HELP_RESTORE_FILES" ascii //weight: 1
        $x_1_5 = "\\RESTORE_FILES" ascii //weight: 1
        $x_1_6 = "CryptoWall" ascii //weight: 1
        $x_1_7 = "Your Personal PAGE(using TOR):" ascii //weight: 1
        $x_1_8 = {53 75 62 6a 65 63 74 3d 25 73 26 6b 65 79 3d 25 73 26 61 64 64 72 3d 25 73 26 73 69 7a 65 3d 25 6c 6c 64 26 76 65 72 73 69 6f 6e 3d 25 73 26 4f 53 3d 25 6c 64 26 49 44 3d 25 64 26 67 61 74 65 3d 25 73 26 69 70 3d 25 73 26 69 6e 73 74 5f 69 64 3d 25 58 25 58 25 58 25 58 25 58 25 58 25 58 25 58 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win32_Tescrypt_A_2147692253_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tescrypt.A"
        threat_id = "2147692253"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tescrypt"
        severity = "7"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = "addr=%s&files=%lld&size=%lld&version=%s&date=%lld&OS=%ld&ID=%d&subid=%d&gate=G%d" ascii //weight: 4
        $x_4_2 = {66 69 6c 65 73 3d 25 [0-2] 64 26 73 69 7a 65 3d 25 [0-2] 64 26 76 65 72 73 69 6f 6e 3d 25 73}  //weight: 4, accuracy: Low
        $x_4_3 = "Subject=ping&addr=%s&&version=%s&date=%lld&OS=%ld&ID=%d&subid=%d" ascii //weight: 4
        $x_4_4 = "%s&addr=%s&files=%d&size=%d&version=%s&date=%lld&OS=%ld&ID=%d&subid=%d&gate=G%d" ascii //weight: 4
        $x_4_5 = "%lld&OS=%ld&ID=%d&subid=%d&gate=G%d&is_admin=%d&is_64=%d&ip=%s&exe_type=" ascii //weight: 4
        $x_4_6 = "%S%s%S%s&files=%lld&size=%lld&version=%s&date=" ascii //weight: 4
        $x_4_7 = "date=%lld&OS=%ld&ID=%d&subid=%d&gate=G%d&is_admin=%d&is_64=%d&ip=%s" ascii //weight: 4
        $x_3_8 = "SendPing 2Tor Exit =%s" ascii //weight: 3
        $x_1_9 = {2f 73 74 61 74 65 [0-2] 2e 70 68 70 3f 25 73}  //weight: 1, accuracy: Low
        $x_1_10 = {2f 74 73 64 66 65 77 72 [0-2] 2e 70 68 70 3f 25 73}  //weight: 1, accuracy: Low
        $x_1_11 = "delete shadows /all" ascii //weight: 1
        $x_1_12 = "---!!!Done!!!---" ascii //weight: 1
        $x_1_13 = "!!!-key = %s -!!!" ascii //weight: 1
        $x_1_14 = "\"File decryption button\" malfunction use one of our gates:" ascii //weight: 1
        $x_1_15 = "All files Decrypted Everything is fine, now decrypting all files." ascii //weight: 1
        $x_1_16 = "crypto13" ascii //weight: 1
        $x_1_17 = "Enter Decryption key here" ascii //weight: 1
        $x_1_18 = "Enter Verification key here" ascii //weight: 1
        $x_1_19 = "Decryption key and Verification key is wrong" ascii //weight: 1
        $x_1_20 = "Click to copy Bitcoin address to clipboard" ascii //weight: 1
        $x_1_21 = "Click to Free Decryption on site" ascii //weight: 1
        $x_1_22 = "Your personal files are encrypted!" ascii //weight: 1
        $x_1_23 = "Your files have been safely encrypted on this PC: photos,videos, documents,etc." ascii //weight: 1
        $x_1_24 = "Everything is fine, now decrypting all files." ascii //weight: 1
        $x_1_25 = "In order to decrypt the files press button to open your personal" ascii //weight: 1
        $x_1_26 = "Your payment is not received !!!" ascii //weight: 1
        $x_1_27 = "!!!Decrypt your files!!!" ascii //weight: 1
        $x_1_28 = "!!!Rescue your files!!!" ascii //weight: 1
        $x_1_29 = "!!!SAFE  your files!!!" ascii //weight: 1
        $x_1_30 = "\\CryptoLocker.lnk" ascii //weight: 1
        $x_1_31 = "\\Save_Files.lnk" ascii //weight: 1
        $x_1_32 = "\\HELP_TO_DECRYPT_YOUR_FILES" ascii //weight: 1
        $x_1_33 = "\\HELP_TO_SAVE_YOUR_FILES" ascii //weight: 1
        $x_1_34 = "\\RECOVERY_KEY.TXT" ascii //weight: 1
        $x_1_35 = "System1230123" ascii //weight: 1
        $x_1_36 = "Crypted&key=" ascii //weight: 1
        $x_1_37 = "Ping&key=" ascii //weight: 1
        $x_1_38 = {46 69 6c 65 20 64 65 63 72 79 70 74 69 6f 6e 20 73 69 74 65 00}  //weight: 1, accuracy: High
        $x_2_39 = "\\HELP_RESTORE_FILES" ascii //weight: 2
        $x_2_40 = "Any attempt to remove or corrupt this software will result" ascii //weight: 2
        $x_2_41 = {53 75 62 6a 65 63 74 3d 43 72 79 00}  //weight: 2, accuracy: High
        $x_2_42 = "---!!!FINE!!!---" ascii //weight: 2
        $x_2_43 = "VV %d" ascii //weight: 2
        $x_2_44 = "7tno4hib47vlep5o" ascii //weight: 2
        $x_2_45 = "tkj3higtqlvohs7z" ascii //weight: 2
        $x_2_46 = "qcuikaiye577q3p2" ascii //weight: 2
        $x_2_47 = "dpckd2ftmf7lelsa" ascii //weight: 2
        $x_2_48 = "dslhufdks3" wide //weight: 2
        $x_4_49 = {8b 44 24 60 8d 57 36 68 ?? ?? ?? ?? 50 c7 44 24 26 36 00 00 00 89 54 24 1e 66 c7 44 24 1c 42 4d}  //weight: 4, accuracy: Low
        $x_4_50 = {8d 4c 24 18 8d 57 36 51 c7 44 24 2e 36 00 00 00 89 54 24 26 66 c7 44 24 24 42 4d}  //weight: 4, accuracy: High
        $x_4_51 = {8d 57 36 68 ?? ?? ?? ?? c7 44 24 3e 36 00 00 00 89 54 24 36 66 c7 44 24 34 42 4d}  //weight: 4, accuracy: Low
        $x_4_52 = {8d 57 36 50 c7 44 24 3e 36 00 00 00 89 54 24 36 66 c7 44 24 34 42 4d}  //weight: 4, accuracy: High
        $x_4_53 = {74 30 8d 44 24 04 8d 50 01 8d a4 24 00 00 00 00 8a 08 83 c0 01 84 c9 75 f7 2b c2 56 50 8d 44 24 0c 6a 01 50 e8 ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? 83 c4 14 8b 8c 24 04 10 00 00}  //weight: 4, accuracy: Low
        $x_4_54 = {74 19 8d 44 24 04 50 68 ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? 83 c4 10 8b 8c 24 04 10 00 00 5e 33 cc e8 ?? ?? ?? ?? 81 c4 04 10 00 00 c3}  //weight: 4, accuracy: Low
        $x_4_55 = {74 19 8d 54 24 04 52 68 ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? 83 c4 10 8b 8c 24 04 20 00 00 5e 33 cc e8 ?? ?? ?? ?? 81 c4 04 20 00 00 c3}  //weight: 4, accuracy: Low
        $x_3_56 = {b8 42 4d 00 00 51 c7 44 24 3e 36 00 00 00 89 54 24 36 66 89 44 24 34 c7 44 24 2c 00 00 00 00 ff 15}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*))) or
            ((3 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Tescrypt_B_2147693164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tescrypt.B"
        threat_id = "2147693164"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tescrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "in case of \"File decryption button\" malfunction use one of our gates:" wide //weight: 1
        $x_1_2 = "&date=%lld&OS=%ld&ID=%d&subid=%d&gate=G%d&is_admin=%d&is_64=%d&ip=%s&exe_type=%d" ascii //weight: 1
        $x_1_3 = "Your personal files are encrypted!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Tescrypt_2147693915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tescrypt"
        threat_id = "2147693915"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tescrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $n_100_1 = {54 65 73 6c 61 43 72 79 70 74 44 65 63 6f 64 65 72 2e 64 6c 6c 00 47 65 74 53 70 65 63 69 61 6c 53 74 61 74 69 73 74 69 63 73 43 6f 75 6e 74 00}  //weight: -100, accuracy: High
        $n_100_2 = {70 74 00 50 65 74 79 61 44 65 63 72 79 70 74 4b 65 79 00 53 63 61 6e 41 6e 64 44 65 63 72 79 70 74 00 53 65 74 44 65 63 72 79 70 74 50 61 74 68}  //weight: -100, accuracy: High
        $n_100_3 = "/inf.safe.360.cn/api/key?key=" ascii //weight: -100
        $x_2_4 = "ROOT\\SecurityCenter2" ascii //weight: 2
        $x_2_5 = "No-Antivirus" ascii //weight: 2
        $x_2_6 = ".ibank" ascii //weight: 2
        $x_2_7 = ".wallet" ascii //weight: 2
        $x_4_8 = "Unlock_files_" ascii //weight: 4
        $x_4_9 = "Alma Locker" ascii //weight: 4
        $x_4_10 = "Your files are encrypted!" ascii //weight: 4
        $x_4_11 = {83 fa 07 7c 0e 7f 07 3d ff 6f 40 93 76 05 83 c8 ff 8b d0}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_4_*) and 3 of ($x_2_*))) or
            ((3 of ($x_4_*) and 1 of ($x_2_*))) or
            ((4 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Tescrypt_C_2147706645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tescrypt.C"
        threat_id = "2147706645"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tescrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 c0 c1 c2 07 33 d0 83 c1 02 0f b7 01 66 85 c0 75 ed}  //weight: 1, accuracy: High
        $x_1_2 = {3b fb 74 f3 81 ff 00 00 80 13 77 eb}  //weight: 1, accuracy: High
        $x_1_3 = {b9 de ad be ef 39 08 75 05 33 f6 46 eb c6}  //weight: 1, accuracy: High
        $x_1_4 = {68 8a 01 00 00 68 ?? ?? ?? ?? 57 89 9d ?? ?? ff ff ff d6 85 c0 75 2a}  //weight: 1, accuracy: Low
        $x_1_5 = "%s\\_%s_%s.TXT" wide //weight: 1
        $x_1_6 = "%s\\_%s_%s.HTML" wide //weight: 1
        $x_1_7 = "bcdedit.exe /set {current} recoveryenabled off" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Tescrypt_C_2147706645_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tescrypt.C"
        threat_id = "2147706645"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tescrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".tor2web" ascii //weight: 1
        $x_1_2 = "bcdedit.exe /set {current} bootstatuspolicy IgnoreAllFailures" ascii //weight: 1
        $x_1_3 = "bcdedit.exe /set {current} recoveryenabled off" ascii //weight: 1
        $x_1_4 = "%s\\HOWTO_RESTORE_FILES." wide //weight: 1
        $x_1_5 = "\\recover_file_" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Tescrypt_C_2147706645_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tescrypt.C"
        threat_id = "2147706645"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tescrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 00 73 00 5c 00 68 00 6f 00 77 00 74 00 6f 00 5f 00 72 00 65 00 63 00 6f 00 76 00 65 00 72 00 5f 00 66 00 69 00 6c 00 65 00 73 00 2e 00 74 00 78 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {25 00 73 00 5c 00 68 00 6f 00 77 00 74 00 6f 00 5f 00 72 00 65 00 63 00 6f 00 76 00 65 00 72 00 5f 00 66 00 69 00 6c 00 65 00 73 00 2e 00 62 00 6d 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {25 00 73 00 5c 00 48 00 4f 00 57 00 54 00 4f 00 5f 00 52 00 45 00 53 00 54 00 4f 00 52 00 45 00 5f 00 46 00 49 00 4c 00 45 00 53 00 2e 00 68 00 74 00 6d 00 [0-1] 00}  //weight: 1, accuracy: Low
        $x_1_4 = {25 00 73 00 5c 00 48 00 4f 00 57 00 54 00 4f 00 5f 00 52 00 45 00 53 00 54 00 4f 00 52 00 45 00 5f 00 46 00 49 00 4c 00 45 00 53 00 2e 00 62 00 6d 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {25 00 73 00 5c 00 76 00 63 00 77 00 25 00 73 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {25 00 73 00 5c 00 25 00 73 00 2d 00 61 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {72 00 65 00 63 00 6f 00 76 00 65 00 72 00 5f 00 66 00 69 00 6c 00 65 00 5f 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = "All your files were encrypted with the public key, which has been transferred to your computer via the Internet." ascii //weight: 1
        $x_1_9 = {73 69 74 65 20 28 6f 72 20 54 4f 52 (20|2d 42 72 6f 77 73) 27 73 29 20 64 69 72 65 63 74 6c 79 29 3a}  //weight: 1, accuracy: Low
        $x_1_10 = ".onion/%S</font><br>" ascii //weight: 1
        $x_1_11 = "suggest you do not waste valuable time searching for other solutions because they do not exist." ascii //weight: 1
        $x_1_12 = "Especially for you, on our server was generated the secret key" ascii //weight: 1
        $x_1_13 = "Alas, if you do not take the necessary measures for the specified time then the conditions for obtaining" ascii //weight: 1
        $x_1_14 = {76 73 73 61 00 00 00 00 64 6d 69 6e 2e 65 78 65 00 00 00 00 64 65 6c 65 74 65 00 00 73 68 61 64 6f 77 73 00 00 00 00 00 2f 61 6c 6c 00 00 00 00 00 00 2f 51 75 69 65 74 00}  //weight: 1, accuracy: High
        $x_1_15 = "SECRET SERVER!!!" ascii //weight: 1
        $x_1_16 = "two ways you can choose: wait for a miracle and get your price doubled, or start obtaining BTC NOW, and restore your data easy way." ascii //weight: 1
        $x_1_17 = "irrevocably changed, you will not be able to work with them, read them or see them," ascii //weight: 1
        $x_1_18 = {59 6f 75 72 20 70 65 72 73 6f 6e 61 6c 20 70 61 67 65 20 28 75 73 69 6e 67 20 54 4f 52 2d 42 72 6f 77 73 65 72 29 3a 20 18 00 2e 6f 6e 69 6f 6e 2f 25 53}  //weight: 1, accuracy: Low
        $x_1_19 = {2d 2d 3e 53 65 63 72 65 74 20 53 65 72 76 65 72 21 21 21 0a}  //weight: 1, accuracy: High
        $x_1_20 = "If You have really valuable data, you better not waste your time, because there is no other way to get your files, except make a payment." ascii //weight: 1
        $x_1_21 = "!!! Specially for your PC was generated personal RSA-4096 KEY, both public and private." ascii //weight: 1
        $x_1_22 = {21 21 21 20 59 6f 75 72 20 70 65 72 73 6f 6e 61 6c 20 70 61 67 65 20 69 6e 20 54 4f 52 20 42 72 6f 77 73 65 72 3a 20 18 00 2e 6f 6e 69 6f 6e 2f 25 53}  //weight: 1, accuracy: Low
        $x_1_23 = {5f 00 46 00 49 00 4c 00 45 00 53 00 2e 00 48 00 54 00 4d 00 00 00 00 00 25 00 73 00 5c 00 48 00 6f 00 77 00 74 00 6f 00 5f 00 52 00 65 00 73 00 74 00 6f 00 72 00 65 00 25 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_24 = "--> structure and data within your files have been irrevocably <!--" ascii //weight: 1
        $x_1_25 = {2d 2d 3e 53 65 63 72 65 74 20 20 3c 21 2d 2d [0-48] 2d 2d 3e 53 65 72 76 65 72 21 21 21 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Ransom_Win32_Tescrypt_D_2147707630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tescrypt.D"
        threat_id = "2147707630"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tescrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {99 b9 7a 00 00 00 f7 f9 8b f2 83 fe 61 7c ec 6a 01 e8 ?? ?? ?? ?? 8b 55 08 83 c4 04 6a 0f 66 89 34 7a ff 15 ?? ?? ?? ?? 47 3b fb 7c 1f 00 [0-15] ff 15 ?? ?? ?? ?? 50 e8}  //weight: 2, accuracy: Low
        $x_2_2 = {52 ff d7 83 c4 08 85 c0 74 16 68 42 a8 6f 9e 6a 01 6a 00 e8 ?? ?? ?? ?? 83 c4 0c 6a 00 56 ff d0 05 00 68}  //weight: 2, accuracy: Low
        $x_1_3 = "NOT YOUR LANGUAGE? USE <a href=\"https://translate.google.com\"" ascii //weight: 1
        $x_1_4 = {59 6f 75 72 20 70 65 72 73 6f 6e 61 6c 20 [0-9] 54 4f 52 ?? 42 72 6f 77 73 65 72 [0-5] 20 ?? ?? ?? ?? ?? ?? ?? ?? [0-8] 2e 6f 6e 69 6f 6e 2f 25 53}  //weight: 1, accuracy: Low
        $x_1_5 = {68 00 65 00 6c 00 70 00 5f 00 72 00 65 00 63 00 6f 00 76 00 65 00 72 00 5f 00 69 00 6e 00 73 00 74 00 72 00 75 00 63 00 74 00 69 00 6f 00 6e 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 00 5c 00 72 00 65 00 63 00 6f 00 76 00 65 00 72 00 5f 00 66 00 69 00 6c 00 65 00 5f 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Tescrypt_E_2147707849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tescrypt.E"
        threat_id = "2147707849"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tescrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 ff d7 83 c4 08 85 c0 74 16 68 42 a8 6f 9e 6a 01 6a 00 e8 ?? ?? ?? ?? 83 c4 0c 6a 00 56 ff d0 05 00 68}  //weight: 1, accuracy: Low
        $x_1_2 = "\\recover_file_" wide //weight: 1
        $x_1_3 = "bcdedit.exe /set {current} bootstatuspolicy IgnoreAllFailures" ascii //weight: 1
        $x_1_4 = "bcdedit.exe /set {current} recoveryenabled off" ascii //weight: 1
        $x_1_5 = {68 00 65 00 6c 00 70 00 5f 00 72 00 65 00 63 00 6f 00 76 00 65 00 72 00 5f 00 69 00 6e 00 73 00 74 00 72 00 75 00 63 00 74 00 69 00 6f 00 6e 00 73 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Tescrypt_G_2147708208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tescrypt.G"
        threat_id = "2147708208"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tescrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {de ad be ef b9 10 00 00 00 be ?? ?? ?? ?? bf ?? ?? ?? ?? f3 a5 b8 ?? ?? ?? ?? 83 c4 18 a4}  //weight: 1, accuracy: Low
        $x_1_2 = ".onion.to/%S" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Tescrypt_H_2147709013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tescrypt.H"
        threat_id = "2147709013"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tescrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {3d 2c a1 02 48 75}  //weight: 3, accuracy: High
        $x_1_2 = {e8 0a 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {e8 0d 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {c7 00 a9 68 a8 56}  //weight: 1, accuracy: High
        $x_1_5 = {c7 00 b3 eb 36 e4}  //weight: 1, accuracy: High
        $x_1_6 = {c7 40 0c af 0b a7 70}  //weight: 1, accuracy: High
        $x_2_7 = {73 68 61 64 6f 77 63 6f 70 79 [0-16] 64 65 6c 65 74 65 [0-16] 2f 6e 6f 69 6e 74 65 72 61 63 74 69 76 65 [0-16] 6f 70 65 6e [0-16] 72 75 6e 61 73}  //weight: 2, accuracy: Low
        $x_1_8 = {8d 49 00 8d 04 5b 8b 4c 86 14 8d 44 86 10 89 45 f0 8b 00 89 45 f8 85 c9 74 14}  //weight: 1, accuracy: High
        $x_1_9 = {81 f9 80 00 00 00 72 1c 83 3d ac f1 47 00 00 74 13 57 56 83 e7 0f 83 e6 0f 3b fe 5e 5f 75 05 e9 ?? ?? 00 00 f7 c7 03 00 00 00 75 14 c1 e9 02 83 e2 03 83 f9 08 72 29 f3 a5}  //weight: 1, accuracy: Low
        $x_1_10 = {01 39 8b 7d fc 01 79 04 8b 19 8b 79 04 c1 c2 1e 03 51 08 89 51 08 8b 51 0c 03 d6 89 51 0c 8b 51 10 03 55 f0 ff 4d 0c 89 51 10 74 1b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Tescrypt_I_2147709119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tescrypt.I"
        threat_id = "2147709119"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tescrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 5f 5f 73 79 73 5f 32 33 34 32 33 38 32 33 33 32 39 35 00}  //weight: 2, accuracy: High
        $x_2_2 = {00 53 6f 66 74 77 61 72 65 5c 78 78 78 73 79 73 5c 00}  //weight: 2, accuracy: High
        $x_1_3 = {00 45 6e 61 62 6c 65 4c 69 6e 6b 65 64 43 6f 6e 6e 65 63 74 69 6f 6e 73 00}  //weight: 1, accuracy: High
        $x_1_4 = "%s\\%s+%s." ascii //weight: 1
        $x_1_5 = "%s\\help_recover_instructions" ascii //weight: 1
        $x_1_6 = "_H_e_l_p_RECOVER_INSTRUCTIONS" ascii //weight: 1
        $x_1_7 = "!!! Your personal identification ID: %S" ascii //weight: 1
        $x_1_8 = {2f 73 65 74 20 7b 63 75 72 72 65 6e 74 7d 20 62 6f 6f 74 73 74 61 74 75 73 70 6f 6c 69 63 79 20 49 67 6e 6f 72 65 41 6c 6c 46 61 69 6c 75 72 65 73 00}  //weight: 1, accuracy: High
        $x_1_9 = {2f 73 65 74 20 7b 63 75 72 72 65 6e 74 7d 20 [0-32] 20 6f 66 66 00}  //weight: 1, accuracy: Low
        $x_1_10 = {73 68 61 64 6f 77 73 [0-16] 2f 61 6c 6c [0-16] 2f 51 75 69 65 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Tescrypt_J_2147709215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tescrypt.J"
        threat_id = "2147709215"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tescrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d c7 04 00 00 75 15 68 34 08 00 00 ff 15 ?? ?? ?? ?? 8d 45 c0 50 ff d6 85 c0 74 de}  //weight: 1, accuracy: Low
        $x_1_2 = {76 73 73 61 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 64 6d 69 6e 00}  //weight: 1, accuracy: High
        $x_1_4 = "shadows" ascii //weight: 1
        $x_1_5 = "/all" ascii //weight: 1
        $x_1_6 = "/Quiet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win32_Tescrypt_O_2147709904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tescrypt.O"
        threat_id = "2147709904"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tescrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {52 ff d7 83 c4 08 85 c0 75 3f 8d 85 fc df ff ff 68 ?? ?? ?? ?? 50 ff d7 83 c4 08 85 c0 75 2a}  //weight: 2, accuracy: Low
        $x_1_2 = "\\recover_file_" wide //weight: 1
        $x_1_3 = "%s\\_ReCoVeRy_.TXT" wide //weight: 1
        $x_1_4 = "%s\\_ReCoVeRy_%s" wide //weight: 1
        $x_1_5 = "%s\\_ReCoVeRy_.png" wide //weight: 1
        $x_1_6 = "0987skfg998jkh89345jk987437k" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Tescrypt_Q_2147710080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tescrypt.Q"
        threat_id = "2147710080"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tescrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Sub=%s&dh=%s&addr=%s&size=%lld&version=4.0&OS=%ld&ID=%d&inst_id=%X%X%X%X%X%X%X%X" ascii //weight: 5
        $x_2_2 = "Your personal identification ID: %S" ascii //weight: 2
        $x_2_3 = "Your personal page Tor-Browser" ascii //weight: 2
        $x_2_4 = "no other option rather than paying" ascii //weight: 2
        $x_2_5 = "You won't be able to use, read, see or work with them anymore" ascii //weight: 2
        $x_1_6 = {2e 6f 6e 69 6f 6e 2f 25 53 0d 0a}  //weight: 1, accuracy: High
        $x_1_7 = {2e 63 6f 6d 2f 25 53 0d 0a}  //weight: 1, accuracy: High
        $x_1_8 = {2e 61 74 2f 25 53 0d 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Tescrypt_R_2147710130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tescrypt.R"
        threat_id = "2147710130"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tescrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 c0 c1 c1 07 83 c2 02 33 c8 0f b7 02 66 85 c0 75 ed 81 f9 8e fe 1f 4b 74 27}  //weight: 1, accuracy: High
        $x_1_2 = {68 5c 01 00 00 68 ?? ?? ?? ?? 53 c7 85 ?? ?? ff ff 00 00 00 00 ff 15 ?? ?? ?? ?? 85 c0 74 a8}  //weight: 1, accuracy: Low
        $x_1_3 = {68 f0 9a b8 6f 6a 01 6a 00 e8 ?? ?? ?? ?? 8b 4d 08 83 c4 0c 6a 00 6a 00 6a 00 51 6a 00 6a 00 ff d0}  //weight: 1, accuracy: Low
        $x_1_4 = {68 bc 02 00 00 6a 00 6a 00 c7 06 00 00 00 00 6a 00 66 0f ef c0 66 0f d6 46 04 6a 12 c7 46 0c 00 00 00 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Tescrypt_A_2147710259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tescrypt.A!!Tescrypt.gen!A"
        threat_id = "2147710259"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tescrypt"
        severity = "Critical"
        info = "Tescrypt: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 c0 c1 c1 07 83 c2 02 33 c8 0f b7 02 66 85 c0 75 ed 81 f9 8e fe 1f 4b 74 27}  //weight: 1, accuracy: High
        $x_1_2 = {68 5c 01 00 00 68 ?? ?? ?? ?? 53 c7 85 ?? ?? ff ff 00 00 00 00 ff 15 ?? ?? ?? ?? 85 c0 74 a8}  //weight: 1, accuracy: Low
        $x_1_3 = {68 f0 9a b8 6f 6a 01 6a 00 e8 ?? ?? ?? ?? 8b 4d 08 83 c4 0c 6a 00 6a 00 6a 00 51 6a 00 6a 00 ff d0}  //weight: 1, accuracy: Low
        $x_1_4 = {68 42 a8 6f 9e}  //weight: 1, accuracy: High
        $x_1_5 = {68 d5 b0 3e 72}  //weight: 1, accuracy: High
        $x_1_6 = {68 60 a2 8a 76}  //weight: 1, accuracy: High
        $x_1_7 = "Your data was secured using a strong encryption with RSA4096." ascii //weight: 1
        $x_1_8 = "It means that on a structural level your files have been transformed" ascii //weight: 1
        $x_1_9 = "You won't be able to use , read , see or work with them anymore" ascii //weight: 1
        $x_1_10 = "You can wait for a while until the price of a private key will raise" ascii //weight: 1
        $x_1_11 = "You can start getting BitCoins right now and get access to your data quite fast" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Tescrypt_A_2147710259_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tescrypt.A!!Tescrypt.gen!A"
        threat_id = "2147710259"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tescrypt"
        severity = "Critical"
        info = "Tescrypt: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8e fe 1f 4b 74}  //weight: 5, accuracy: High
        $x_5_2 = {3d 03 40 00 80 74 14 68 19 2b 90 95}  //weight: 5, accuracy: High
        $x_1_3 = {68 01 3d 1e d2}  //weight: 1, accuracy: High
        $x_1_4 = {68 02 f1 f8 08}  //weight: 1, accuracy: High
        $x_1_5 = {68 05 ad 89 0d}  //weight: 1, accuracy: High
        $x_1_6 = {68 07 be db 80}  //weight: 1, accuracy: High
        $x_1_7 = {68 09 dc 1b 1e}  //weight: 1, accuracy: High
        $x_1_8 = {68 0c fb 14 73}  //weight: 1, accuracy: High
        $x_1_9 = {68 13 11 74 02}  //weight: 1, accuracy: High
        $x_1_10 = {68 19 2b 90 95}  //weight: 1, accuracy: High
        $x_1_11 = {68 25 f5 10 5e}  //weight: 1, accuracy: High
        $x_1_12 = {68 26 ef 02 98}  //weight: 1, accuracy: High
        $x_1_13 = {68 28 de 73 75}  //weight: 1, accuracy: High
        $x_1_14 = {68 2c 01 95 12}  //weight: 1, accuracy: High
        $x_1_15 = {68 2f 00 10 15}  //weight: 1, accuracy: High
        $x_1_16 = {68 32 0e 48 9c}  //weight: 1, accuracy: High
        $x_1_17 = {68 34 55 35 db}  //weight: 1, accuracy: High
        $x_1_18 = {68 3a e0 48 ef}  //weight: 1, accuracy: High
        $x_1_19 = {68 3e 8d 61 be}  //weight: 1, accuracy: High
        $x_1_20 = {68 42 a8 6f 9e}  //weight: 1, accuracy: High
        $x_1_21 = {68 46 85 5d c9}  //weight: 1, accuracy: High
        $x_1_22 = {68 49 7d 99 28}  //weight: 1, accuracy: High
        $x_1_23 = "hR$C2" ascii //weight: 1
        $x_1_24 = {68 57 95 aa de}  //weight: 1, accuracy: High
        $x_1_25 = {68 59 c7 ec d4}  //weight: 1, accuracy: High
        $x_1_26 = {68 60 a2 8a 76}  //weight: 1, accuracy: High
        $x_1_27 = {68 62 29 21 1a}  //weight: 1, accuracy: High
        $x_1_28 = {68 6a 85 13 9f}  //weight: 1, accuracy: High
        $x_1_29 = {68 6b e1 7f 48}  //weight: 1, accuracy: High
        $x_1_30 = {68 6d d1 b2 4c}  //weight: 1, accuracy: High
        $x_1_31 = {68 71 a1 5e 72}  //weight: 1, accuracy: High
        $x_1_32 = {68 78 9c d0 1a}  //weight: 1, accuracy: High
        $x_1_33 = {68 7c 01 f0 5a}  //weight: 1, accuracy: High
        $x_1_34 = {68 81 de ec 67}  //weight: 1, accuracy: High
        $x_1_35 = {68 86 67 41 6b}  //weight: 1, accuracy: High
        $x_1_36 = {68 8a 96 78 bf}  //weight: 1, accuracy: High
        $x_1_37 = {68 8f c8 0b 57}  //weight: 1, accuracy: High
        $x_1_38 = {68 95 23 26 bc}  //weight: 1, accuracy: High
        $x_1_39 = {68 95 69 27 f2}  //weight: 1, accuracy: High
        $x_1_40 = {68 9b 90 c4 8a}  //weight: 1, accuracy: High
        $x_1_41 = {68 9d 29 a4 99}  //weight: 1, accuracy: High
        $x_1_42 = {68 a1 87 55 4d}  //weight: 1, accuracy: High
        $x_1_43 = {68 a1 b0 5c 72}  //weight: 1, accuracy: High
        $x_1_44 = {68 af 12 3d 1b}  //weight: 1, accuracy: High
        $x_1_45 = {68 c0 0f 40 3e}  //weight: 1, accuracy: High
        $x_1_46 = {68 c1 ea 9d 27}  //weight: 1, accuracy: High
        $x_1_47 = {68 c3 d1 3f 0f}  //weight: 1, accuracy: High
        $x_1_48 = {68 c8 39 03 24}  //weight: 1, accuracy: High
        $x_1_49 = {68 c9 f0 f0 81}  //weight: 1, accuracy: High
        $x_1_50 = {68 d1 8a 31 46}  //weight: 1, accuracy: High
        $x_1_51 = {68 d5 70 34 6b}  //weight: 1, accuracy: High
        $x_1_52 = {68 d5 b0 3e 72}  //weight: 1, accuracy: High
        $x_1_53 = {68 d7 3d 59 08}  //weight: 1, accuracy: High
        $x_1_54 = {68 d9 38 45 17}  //weight: 1, accuracy: High
        $x_1_55 = {68 dc 67 21 7a}  //weight: 1, accuracy: High
        $x_1_56 = {68 e4 55 9f da}  //weight: 1, accuracy: High
        $x_1_57 = {68 eb 3d 03 84}  //weight: 1, accuracy: High
        $x_1_58 = {68 ee ea c0 1f}  //weight: 1, accuracy: High
        $x_1_59 = {68 f0 97 a0 90}  //weight: 1, accuracy: High
        $x_1_60 = {68 f0 9a b8 6f}  //weight: 1, accuracy: High
        $x_1_61 = {68 f3 74 43 c5}  //weight: 1, accuracy: High
        $x_1_62 = {68 f5 72 99 3d}  //weight: 1, accuracy: High
        $x_1_63 = {68 f6 35 3d d6}  //weight: 1, accuracy: High
        $x_1_64 = {68 fb 96 32 22}  //weight: 1, accuracy: High
        $x_1_65 = {68 fc 7e b8 48}  //weight: 1, accuracy: High
        $x_1_66 = {68 fc da 94 48}  //weight: 1, accuracy: High
        $x_1_67 = {68 fe 93 43 77}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((20 of ($x_1_*))) or
            ((1 of ($x_5_*) and 15 of ($x_1_*))) or
            ((2 of ($x_5_*) and 10 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Tescrypt_A_2147710259_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tescrypt.A!!Tescrypt.gen!A"
        threat_id = "2147710259"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tescrypt"
        severity = "Critical"
        info = "Tescrypt: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 25 58 25 58 25 58 25 58 25 58 25 58 25 58 25 58 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 58 58 58 58 58 58 58 58 58 58 58 58 58 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 00}  //weight: 1, accuracy: High
        $x_1_4 = "shadowcopy delete /nointeractive" ascii //weight: 1
        $x_2_5 = "\\-!recover!-!file!-.txt" ascii //weight: 2
        $x_2_6 = "\\desctop._ini" ascii //weight: 2
        $x_1_7 = "S-1-5-18\\Software\\Axronics" ascii //weight: 1
        $x_1_8 = "\\Run /v %s /t REG_SZ  /d \"%s\" /f" ascii //weight: 1
        $x_1_9 = "Mozilla/5.0 (Windows NT 6.3 rv:11.0) like Gecko" ascii //weight: 1
        $x_2_10 = "*/*, Crypted, Ping, data=%s" ascii //weight: 2
        $x_1_11 = "EnableLinkedConnections" ascii //weight: 1
        $x_1_12 = "D:P(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;IU)(A;OICI;FA;;;SY)" ascii //weight: 1
        $x_1_13 = "wlrmdr" ascii //weight: 1
        $x_2_14 = {78 65 3a 5a 6f 6e 65 2e 49 64 65 6e 74 69 66 69 65 72 00}  //weight: 2, accuracy: High
        $x_2_15 = "Delete Shadows /all /quiet" ascii //weight: 2
        $x_1_16 = {00 6e 65 77 5f 64 61 74 61 71 00}  //weight: 1, accuracy: High
        $x_1_17 = {00 74 61 73 6b 6d 67 00}  //weight: 1, accuracy: High
        $x_1_18 = {00 72 65 67 65 64 69 00}  //weight: 1, accuracy: High
        $x_1_19 = {00 70 72 6f 63 65 78 00}  //weight: 1, accuracy: High
        $x_1_20 = {00 6d 73 63 6f 6e 66 69 00}  //weight: 1, accuracy: High
        $x_2_21 = {00 43 72 79 70 74 65 64 00 50 69 6e 67 00 64 61 74 61 3d 25 73 00}  //weight: 2, accuracy: High
        $x_2_22 = ".replace(/\\\\\\\\{id\\\\\\\\}/g," ascii //weight: 2
        $x_1_23 = "Your personal homepage Tor-Browser" ascii //weight: 1
        $x_1_24 = "Your personal ID" ascii //weight: 1
        $x_4_25 = "Sub=%s&dh=%s&addr=%s&size=%lld&version=" ascii //weight: 4
        $x_4_26 = "&OS=%ld&ID=%d&inst_id=%X%X%X%X%X%X%X%X" ascii //weight: 4
        $x_4_27 = {6f 77 73 20 c7 45 ?? 2f 61 6c 6c c7 45 ?? 20 2f 51 75 c7 45 ?? 69 65 74 00 c7 45 ?? 76 73 73 61}  //weight: 4, accuracy: Low
        $x_2_28 = {68 00 10 14 00 53 53 89 5d fc ff 15 ?? ?? ?? ?? 6a ff 50 ff 15 ?? ?? ?? ?? 6a 01 ff 15 ?? ?? ?? ?? cc}  //weight: 2, accuracy: Low
        $x_2_29 = {ff d6 68 e0 93 04 00 53 ff d7 6a 00 6a 00 6a 00 68 ?? ?? ?? ?? 6a 00 6a 00 c7 05 ?? ?? ?? ?? 01 00 00 00 ff d6 68 60 ea 00 00}  //weight: 2, accuracy: Low
        $x_1_30 = {ff d7 3d c7 04 00 00 75 1a 68 b8 0b 00 00}  //weight: 1, accuracy: High
        $x_1_31 = {ff d3 0f bf 55 fc 6a 00 6a 00 83 c2 58}  //weight: 1, accuracy: High
        $x_2_32 = {83 fa 07 7c 0e 7f 07 3d ff 6f 40 93 76 05}  //weight: 2, accuracy: High
        $x_1_33 = {75 08 6a 01 e8 ?? ?? 00 00 59 68 09 04 00 c0}  //weight: 1, accuracy: Low
        $x_2_34 = {8b 45 0c 8b 00 8b 40 14 3b c3 75 ?? 8b c6 66 39 1e 74 ?? 0f b7 08 83 f9 41 72 ?? 83 f9 5a 77}  //weight: 2, accuracy: Low
        $x_1_35 = {ff f0 e1 d2 c3}  //weight: 1, accuracy: High
        $x_1_36 = {ff 3a f5 4f a5}  //weight: 1, accuracy: High
        $x_2_37 = {fe c0 8d 83 26}  //weight: 2, accuracy: High
        $x_4_38 = {6a 00 6a 00 6a 00 ?? ff 15 ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 6a 00 8d [0-8] 68 5c 01 00 00 68 ?? ?? ?? ?? ?? c7 [0-8] 00 00 00 00 ff d6}  //weight: 4, accuracy: Low
        $x_4_39 = {68 08 01 00 00 68 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? 81 [0-8] 08 01 00 00}  //weight: 4, accuracy: Low
        $x_2_40 = {74 13 41 83 f9 2d 72 f1 8d 48 ed 83 f9 11 77 0e 6a 0d}  //weight: 2, accuracy: High
        $x_2_41 = {8b 41 28 ff d0 85 c0 74 08 6a 01 ff 15 ?? ?? ?? ?? 8b 44 24 10 8b 08 8b 51 04 50 ff d2}  //weight: 2, accuracy: Low
        $x_2_42 = {68 80 38 01 00 8d ?? ?? ?? ?? ?? 6a 00 52 e8 ?? ?? ?? ?? 83 c4 0c 68 c8 00 00 00 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((12 of ($x_1_*))) or
            ((1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((6 of ($x_2_*))) or
            ((1 of ($x_4_*) and 8 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_2_*))) or
            ((2 of ($x_4_*) and 4 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*))) or
            ((3 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Tescrypt_T_2147710328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tescrypt.T"
        threat_id = "2147710328"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tescrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 25 58 25 58 25 58 25 58 25 58 25 58 25 58 25 58 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 58 58 58 58 58 58 58 58 58 58 58 58 58 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 00}  //weight: 1, accuracy: High
        $x_1_4 = "shadowcopy delete /nointeractive" ascii //weight: 1
        $x_2_5 = "\\-!recover!-!file!-.txt" ascii //weight: 2
        $x_2_6 = "\\desctop._ini" ascii //weight: 2
        $x_1_7 = "S-1-5-18\\Software\\Axronics" ascii //weight: 1
        $x_1_8 = "\\Run /v %s /t REG_SZ  /d \"%s\" /f" ascii //weight: 1
        $x_1_9 = "Mozilla/5.0 (Windows NT 6.3 rv:11.0) like Gecko" ascii //weight: 1
        $x_2_10 = "*/*, Crypted, Ping, data=%s" ascii //weight: 2
        $x_1_11 = "EnableLinkedConnections" ascii //weight: 1
        $x_1_12 = "D:P(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;IU)(A;OICI;FA;;;SY)" ascii //weight: 1
        $x_1_13 = "wlrmdr" ascii //weight: 1
        $x_2_14 = {78 65 3a 5a 6f 6e 65 2e 49 64 65 6e 74 69 66 69 65 72 00}  //weight: 2, accuracy: High
        $x_2_15 = "Delete Shadows /all /quiet" ascii //weight: 2
        $x_1_16 = {00 6e 65 77 5f 64 61 74 61 71 00}  //weight: 1, accuracy: High
        $x_1_17 = {00 74 61 73 6b 6d 67 00}  //weight: 1, accuracy: High
        $x_1_18 = {00 72 65 67 65 64 69 00}  //weight: 1, accuracy: High
        $x_1_19 = {00 70 72 6f 63 65 78 00}  //weight: 1, accuracy: High
        $x_1_20 = {00 6d 73 63 6f 6e 66 69 00}  //weight: 1, accuracy: High
        $x_2_21 = {00 43 72 79 70 74 65 64 00 50 69 6e 67 00 64 61 74 61 3d 25 73 00}  //weight: 2, accuracy: High
        $x_2_22 = ".replace(/\\\\\\\\{id\\\\\\\\}/g," ascii //weight: 2
        $x_1_23 = "Your personal homepage Tor-Browser" ascii //weight: 1
        $x_1_24 = "Your personal ID" ascii //weight: 1
        $x_4_25 = "Sub=%s&dh=%s&addr=%s&size=%lld&version=" ascii //weight: 4
        $x_4_26 = "&OS=%ld&ID=%d&inst_id=%X%X%X%X%X%X%X%X" ascii //weight: 4
        $x_4_27 = {6f 77 73 20 c7 45 ?? 2f 61 6c 6c c7 45 ?? 20 2f 51 75 c7 45 ?? 69 65 74 00 c7 45 ?? 76 73 73 61}  //weight: 4, accuracy: Low
        $x_2_28 = {68 00 10 14 00 53 53 89 5d fc ff 15 ?? ?? ?? ?? 6a ff 50 ff 15 ?? ?? ?? ?? 6a 01 ff 15 ?? ?? ?? ?? cc}  //weight: 2, accuracy: Low
        $x_2_29 = {ff d6 68 e0 93 04 00 53 ff d7 6a 00 6a 00 6a 00 68 ?? ?? ?? ?? 6a 00 6a 00 c7 05 ?? ?? ?? ?? 01 00 00 00 ff d6 68 60 ea 00 00}  //weight: 2, accuracy: Low
        $x_1_30 = {ff d7 3d c7 04 00 00 75 1a 68 b8 0b 00 00}  //weight: 1, accuracy: High
        $x_1_31 = {ff d3 0f bf 55 fc 6a 00 6a 00 83 c2 58}  //weight: 1, accuracy: High
        $x_2_32 = {83 fa 07 7c 0e 7f 07 3d ff 6f 40 93 76 05}  //weight: 2, accuracy: High
        $x_1_33 = {75 08 6a 01 e8 ?? ?? 00 00 59 68 09 04 00 c0}  //weight: 1, accuracy: Low
        $x_2_34 = {8b 45 0c 8b 00 8b 40 14 3b c3 75 ?? 8b c6 66 39 1e 74 ?? 0f b7 08 83 f9 41 72 ?? 83 f9 5a 77}  //weight: 2, accuracy: Low
        $x_1_35 = {ff f0 e1 d2 c3}  //weight: 1, accuracy: High
        $x_1_36 = {ff 3a f5 4f a5}  //weight: 1, accuracy: High
        $x_2_37 = {fe c0 8d 83 26}  //weight: 2, accuracy: High
        $x_4_38 = {6a 00 6a 00 6a 00 ?? ff 15 ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 6a 00 8d [0-8] 68 5c 01 00 00 68 ?? ?? ?? ?? ?? c7 [0-8] 00 00 00 00 ff d6}  //weight: 4, accuracy: Low
        $x_4_39 = {68 08 01 00 00 68 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? 81 [0-8] 08 01 00 00}  //weight: 4, accuracy: Low
        $x_2_40 = {74 13 41 83 f9 2d 72 f1 8d 48 ed 83 f9 11 77 0e 6a 0d}  //weight: 2, accuracy: High
        $x_2_41 = {8b 41 28 ff d0 85 c0 74 08 6a 01 ff 15 ?? ?? ?? ?? 8b 44 24 10 8b 08 8b 51 04 50 ff d2}  //weight: 2, accuracy: Low
        $x_2_42 = {68 80 38 01 00 8d ?? ?? ?? ?? ?? 6a 00 52 e8 ?? ?? ?? ?? 83 c4 0c 68 c8 00 00 00 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((12 of ($x_1_*))) or
            ((1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((6 of ($x_2_*))) or
            ((1 of ($x_4_*) and 8 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_2_*))) or
            ((2 of ($x_4_*) and 4 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*))) or
            ((3 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Tescrypt_U_2147712045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tescrypt.U"
        threat_id = "2147712045"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tescrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 4f 47 55 45 5f 53 54 41 52 54 00}  //weight: 1, accuracy: High
        $x_1_2 = {52 4f 47 55 45 5f 45 4e 44 00}  //weight: 1, accuracy: High
        $x_1_3 = {0f be 00 85 c0 74 ?? 8b 45 ?? 03 45 ?? 0f be 00 8b 4d ?? 0f af 4d ?? 03 c1 8b 4d ?? 03 4d ?? 0f b6 09 33 c8 8b 45 ?? 03 45 ?? 88 08 8b 45 ?? 40 89 45 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Tescrypt_V_2147716527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tescrypt.V!bit"
        threat_id = "2147716527"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tescrypt"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a d0 02 d1 32 d0 8a d9 2a da 80 ?? ?? 32 ?? ?? 32 d8 88 ?? ?? 40 3b c7 72}  //weight: 2, accuracy: Low
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "All your data was Encrypted" wide //weight: 1
        $x_1_4 = "all DATA will be damaged unrecoverably" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Tescrypt_W_2147721468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tescrypt.W"
        threat_id = "2147721468"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tescrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 34 01 01 41 3b 4d 0c 76 f6}  //weight: 1, accuracy: High
        $x_1_2 = {0f b7 c9 c1 c0 07 33 c1 83 c2 02 0f b7 0a 66 85 c9 75 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Tescrypt_X_2147727193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tescrypt.X!bit"
        threat_id = "2147727193"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tescrypt"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 0f 43 75 ?? 83 7d ?? 10 0f 43 4d ?? 33 d2 f7 75 ?? 8a 04 3a 32 04 33 88 04 19 43 3b 5d ?? 72 d4}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 17 8b c2 c7 45 ?? ?? ?? ?? ?? 25 00 f0 00 00 66 3b 45 ?? 75 0b 81 e2 ff 0f 00 00 03 55 ?? 01 0a 8b 03 46 83 e8 ?? 83 c7 ?? d1 e8 3b f0 72 cf}  //weight: 1, accuracy: Low
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" wide //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" wide //weight: 1
        $x_1_5 = "net start TermService" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Tescrypt_2147745099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tescrypt!MTB"
        threat_id = "2147745099"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tescrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "By54yUW98M345MF967" ascii //weight: 1
        $x_1_2 = "EB3R4n08oIp5u" ascii //weight: 1
        $x_1_3 = "u57a9679o464p9" ascii //weight: 1
        $x_1_4 = "MA7h5Ic73PV89" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Tescrypt_AC_2147795239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tescrypt.AC!MTB"
        threat_id = "2147795239"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tescrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 c8 89 45 ?? 2b f9 25 ?? ?? ?? ?? 8b c7 8d 4d ?? e8 ?? ?? ?? ?? 8b 4d ?? 8b c7 c1 e8 ?? 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? 03 c7 50 8b 45 ?? 03 c3 e8 ?? ?? ?? ?? 8b 4d ?? 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 83 25 ?? ?? ?? ?? ?? 2b 75 ?? 8b 45 ?? 29 45 ?? ff 4d ?? 0f 85 ?? ?? ?? ?? 8b 45 ?? 89 78 ?? 5f 89 30 5e 5b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Tescrypt_AB_2147903119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tescrypt.AB!MTB"
        threat_id = "2147903119"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tescrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 0f 88 4c 24 ?? 8b 54 24 ?? 8b 7c 24 ?? 8a 4c 24 ?? 80 f1 ?? 88 4c 24 ?? 0f be 4c 24 1f 0f be 14 3a 29 ca 88 d1 88 4c 24 ?? 8b 54 24 ?? 8a 4c 24 ?? c7 44 24 ?? ?? ?? ?? ?? 8b 7c 24 ?? 88 0c 17 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Tescrypt_YAA_2147905456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tescrypt.YAA"
        threat_id = "2147905456"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tescrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 c5 81 c0 4c 00 00 00 b9 b2 05 00 00 ba 27 af 2b 2e 30 10 40 49}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Tescrypt_YAB_2147905473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tescrypt.YAB!MTB"
        threat_id = "2147905473"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tescrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 02 29 f0 88 c1 88 4c 24 6f 8a 4c 24}  //weight: 1, accuracy: High
        $x_1_2 = {66 8b 84 24 ?? ?? ?? ?? 66 33 84 24 ?? ?? ?? ?? 66 89 84 24 ?? ?? ?? ?? 8b 4c 24 5c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Tescrypt_NA_2147916369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tescrypt.NA!MTB"
        threat_id = "2147916369"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tescrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "oqwy4fqhukfl[q[er9fhpqey8pfi9[qwef89hju" ascii //weight: 3
        $x_2_2 = "GetShellWindow" ascii //weight: 2
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Tescrypt_ND_2147916379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tescrypt.ND!MTB"
        threat_id = "2147916379"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tescrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "vbdfethi75tyjgfcxvgsrey54trdhf" ascii //weight: 3
        $x_2_2 = "cvgfyti76ighngjtyi76kyghb" ascii //weight: 2
        $x_1_3 = "supperStr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Tescrypt_NB_2147917727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tescrypt.NB!MTB"
        threat_id = "2147917727"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tescrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 ec 08 83 f8 00 0f 95 c3 8a 7c 24 ?? 30 fb f6 c3 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Tescrypt_NC_2147917728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tescrypt.NC!MTB"
        threat_id = "2147917728"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tescrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "abacistabackabacliabacotabacusabacuses" ascii //weight: 3
        $x_2_2 = "n if you like" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Tescrypt_NNL_2147917917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tescrypt.NNL!MTB"
        threat_id = "2147917917"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tescrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "dtnttjtkdtyjt" ascii //weight: 3
        $x_2_2 = "suppekStr" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

