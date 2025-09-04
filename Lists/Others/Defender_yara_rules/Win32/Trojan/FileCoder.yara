rule Trojan_Win32_FileCoder_AT_2147754563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileCoder.AT!MTB"
        threat_id = "2147754563"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[info] file encryptable found : %s" ascii //weight: 1
        $x_1_2 = "[info] entering the folder : %s" ascii //weight: 1
        $x_1_3 = "ENCRYPTOR v0.5" ascii //weight: 1
        $x_1_4 = "[error] can't read the key-file :s" ascii //weight: 1
        $x_1_5 = "key.txt" ascii //weight: 1
        $x_1_6 = "flag.txt" ascii //weight: 1
        $x_1_7 = "****Chiffrement termin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_FileCoder_XY_2147769209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileCoder.XY!MTB"
        threat_id = "2147769209"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 6c 8b 4c 24 60 89 38 5f 89 48 04 8b 8c 24 ?? ?? ?? ?? 5e 5b 33 cc e8 ?? ?? ?? ?? 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {33 f3 2b fe 8b 44 24 74 29 44 24 10 83 6c 24 64 01 0f 85 67 fb ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FileCoder_XZ_2147769521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileCoder.XZ!MTB"
        threat_id = "2147769521"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 68 8b 54 24 60 89 50 04 8b 8c 24 ?? ?? ?? ?? 5f 5e 89 28 5d 5b 33 cc e8 ?? ?? 00 00 81 c4 ?? ?? 00 00 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 68 8b 54 24 60 89 50 04 eb [0-32] 8b 8c 24 ?? ?? ?? ?? 5f 5e 89 28 5d 5b 33 cc e8 ?? ?? 00 00 81 c4 ?? ?? 00 00 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_FileCoder_YY_2147769522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileCoder.YY!MTB"
        threat_id = "2147769522"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 24 8b 44 24 2c 8b 4c 24 30 5f 89 32 5e 89 2c 88 5d 5b 83 c4 18 c3}  //weight: 1, accuracy: High
        $x_1_2 = {6a 40 68 00 10 00 00 52 53 40 00 c6 05 ?? ?? ?? ?? 41 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 6f c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 00 ff 15 ?? ?? ?? ?? 8b 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_FileCoder_XU_2147769690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileCoder.XU!MTB"
        threat_id = "2147769690"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DECRYPT_FILES.TXT" ascii //weight: 1
        $x_1_2 = "compiler\\Kol.pas" ascii //weight: 1
        $x_1_3 = "if you want to restore files, then pay" ascii //weight: 1
        $x_1_4 = "Erica Test Build" ascii //weight: 1
        $x_1_5 = "estore %1 files.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FileCoder_EC_2147850522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileCoder.EC!MTB"
        threat_id = "2147850522"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "__empty.ReNaMeD" ascii //weight: 1
        $x_1_2 = "All your files are belong to us!" ascii //weight: 1
        $x_1_3 = "bin_tests.log" ascii //weight: 1
        $x_1_4 = "cmd.exe /c mimic.bat" wide //weight: 1
        $x_1_5 = "mshta.exe mimic.hta" wide //weight: 1
        $x_1_6 = "mimic.batend" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FileCoder_NFC_2147893671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileCoder.NFC!MTB"
        threat_id = "2147893671"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {e8 fc 87 ff ff 48 89 c1 48 8d 41 ?? 89 59 0c c7 41 08 ?? ?? ?? ?? 66 85 f6 75 08 48 0f b7 35 ce 0f 18 00 66 89 71 04 66 c7 41 06 ?? ?? 8b cb c1 e9 ?? 03 cb c1 f9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FileCoder_ARAT_2147902430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileCoder.ARAT!MTB"
        threat_id = "2147902430"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "service@goodluckday.xyz" ascii //weight: 2
        $x_2_2 = "taskkill /f /im msaccess.exe" ascii //weight: 2
        $x_2_3 = "btc to my address:" ascii //weight: 2
        $x_2_4 = {0d 12 03 28 ?? ?? ?? 0a 0c 08 16 06 1f 10 07 5a 08 8e 69 28 ?? ?? ?? 0a 07 17 58 0b 07 02 32 db}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FileCoder_ARAQ_2147908250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileCoder.ARAQ!MTB"
        threat_id = "2147908250"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "system is encrypted By RANSOMCRYPTO" ascii //weight: 2
        $x_2_2 = "://RansomCrypto_qoia6E1FkoQjefA9ia10.onion" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FileCoder_ARAQ_2147908250_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileCoder.ARAQ!MTB"
        threat_id = "2147908250"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "@TANKIX." wide //weight: 2
        $x_2_2 = "\\BSOD.exe" wide //weight: 2
        $x_2_3 = "d5a01s9u" wide //weight: 2
        $x_2_4 = "EnableLUA" wide //weight: 2
        $x_2_5 = "DisableTaskMgr" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FileCoder_NF_2147909824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileCoder.NF!MTB"
        threat_id = "2147909824"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Kqx+vOUL65B" ascii //weight: 2
        $x_2_2 = "Ki-mUXK4S" ascii //weight: 2
        $x_2_3 = "qQf2kOf" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FileCoder_NF_2147909824_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileCoder.NF!MTB"
        threat_id = "2147909824"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {e9 c1 00 00 00 83 65 c0 00 c7 45 c4 0f 2c 42 00 a1 ?? ?? ?? ?? 8d 4d c0 33 c1 89 45 ?? 8b 45 18 89 45 ?? 8b 45 0c 89}  //weight: 5, accuracy: Low
        $x_1_2 = "encrypted-not-wall.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FileCoder_NF_2147909824_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileCoder.NF!MTB"
        threat_id = "2147909824"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {a1 8c 26 43 00 42 8a 44 10 ff 88 44 17 ff 8b 0d 88 26 43 00 8b 3d 90 26 43 00 3b d1 7c e2 a1 84 26 43 00}  //weight: 3, accuracy: High
        $x_2_2 = {8b 3d 90 26 43 00 33 d2 f7 f1 8a 4c 37 ff 8a 04 17 88 0c 17 8b 0d 90 26 43 00 88 44 31 ff a1 84 26 43 00 8b 3d 14 26 43 00 8b c8 c1 e9 19 c1 e0 07}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FileCoder_NF_2147909824_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileCoder.NF!MTB"
        threat_id = "2147909824"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Cryptowall.htm" ascii //weight: 2
        $x_1_2 = "Send $600 worth of Bitcoin to this address" ascii //weight: 1
        $x_1_3 = "Decrypting... DO NOT CLOSE THE PROGRAM" ascii //weight: 1
        $x_1_4 = "To get the key to decrypt files, you have to paid" ascii //weight: 1
        $x_1_5 = "Our democracy as been hacked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FileCoder_NF_2147909824_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileCoder.NF!MTB"
        threat_id = "2147909824"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "nebezpecnyweb.eu/cmFuc29td2FyZQ/detail.php" ascii //weight: 2
        $x_1_2 = "hijacked" ascii //weight: 1
        $x_1_3 = "REG ADD HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /V Sys" ascii //weight: 1
        $x_1_4 = "ransomware" ascii //weight: 1
        $x_1_5 = "DeleteFiles" ascii //weight: 1
        $x_1_6 = "GetEncryptedFiles" ascii //weight: 1
        $x_1_7 = "decrypting message" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FileCoder_ARAX_2147910935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileCoder.ARAX!MTB"
        threat_id = "2147910935"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d 55 e0 03 d0 40 8a 0c 13 32 0a 88 0c 16 3b c7 72 ee}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FileCoder_ARAX_2147910935_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileCoder.ARAX!MTB"
        threat_id = "2147910935"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 14 07 32 10 ff 85 c4 fd ff ff 88 14 01 33 d2 40 3b d6 72 eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FileCoder_ARAX_2147910935_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileCoder.ARAX!MTB"
        threat_id = "2147910935"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 d1 eb 83 e8 01 89 4d fc 89 45 f4 0f 85 6b ff ff ff}  //weight: 2, accuracy: High
        $x_2_2 = "Global\\FSWiper" wide //weight: 2
        $x_2_3 = "\\ZLWP.tmp" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FileCoder_AMDA_2147931008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileCoder.AMDA!MTB"
        threat_id = "2147931008"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Gaza and the Resistance are victorious. Israel defeated" ascii //weight: 1
        $x_4_2 = {8d 41 e0 3c 5a 77 [0-10] 99 f7 7d [0-24] 5b [0-10] b9 5b 00 00 00 [0-5] f7 f9 8d 4a 20 88 0c 37 46 [0-10] 84 c9 75}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FileCoder_ARAC_2147933302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileCoder.ARAC!MTB"
        threat_id = "2147933302"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 75 18 8a 8c 95 fc fb ff ff 8a 14 30 32 d1 88 14 30 40 3b c7 0f 82 70 ff ff ff}  //weight: 2, accuracy: High
        $x_2_2 = {8b 55 18 03 95 f4 fb ff ff 8a 0a 32 8c 85 f8 fb ff ff 8b 55 18 03 95 f4 fb ff ff 88 0a e9 2e ff ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_FileCoder_ARAE_2147933417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileCoder.ARAE!MTB"
        threat_id = "2147933417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 04 30 30 04 1f ff 46 40 47 8b 46 40 3b 7d 08 72 dc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FileCoder_ZZ_2147951322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileCoder.ZZ!MTB"
        threat_id = "2147951322"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 01 e4 c7 00 03 00 00 00 48 c7 40 08 00 00 00 00 44 89 78 10 48 89 c1 48 83 c1 14 4c 89 f2 4d 89 e0 e8 83 46 05 00 48 8b 4d 10 ba 16 00 00 00 4d 89 e8 4c 8b 7d a8 45 89 f9}  //weight: 1, accuracy: High
        $x_1_2 = {66 83 fb 2e 0f 85 a1 00 00 00 66 45 85 ff 74 10 44 89 f8 83 f0 2e 66 44 09 f0 0f 85 8b 00 00 00 4c 8d 75 a8 41 b8 50 02 00 00 4c 89 f1 48 89 d3 31 d2 e8 77 5b 05 00 48 8b 5b 08 0f 1f 00 48 89 d9 4c 89 f2}  //weight: 1, accuracy: High
        $x_1_3 = {f0 48 ff 07 7e 7f 48 8d 42 1c 48 83 c2 4e 0f 10 00 0f 10 48 10 0f 10 50 1c 0f 11 56 2c 0f 11 4e 20 0f 11 46 10 48 8d 4e 42 41 b8 1e 02 00 00 e8 bf 5a 05 00 48 89 7e 08 66 89 5e 3c 66 44 89 7e 3e 66 44 89 76 40 48 c7 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

