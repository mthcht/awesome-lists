rule Ransom_Win64_HiveCrypt_PA_2147808959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/HiveCrypt.PA!MTB"
        threat_id = "2147808959"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "HiveCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "http://hivecust" ascii //weight: 4
        $x_4_2 = "http://hiveleakdb" ascii //weight: 4
        $x_2_3 = "encrypt_files.go" ascii //weight: 2
        $x_1_4 = "erase_key.go" ascii //weight: 1
        $x_2_5 = "kill_processes.go" ascii //weight: 2
        $x_1_6 = "remove_shadow_copies.go" ascii //weight: 1
        $x_1_7 = "stop_services_windows.go" ascii //weight: 1
        $x_1_8 = "remove_itself_windows.go" ascii //weight: 1
        $x_1_9 = "/encryptor/" ascii //weight: 1
        $x_2_10 = "HOW_TO_DECRYPT.txt" ascii //weight: 2
        $x_1_11 = "FilesEncrypted" ascii //weight: 1
        $x_1_12 = "EncryptionStarted" ascii //weight: 1
        $x_1_13 = "encryptFilesGroup" ascii //weight: 1
        $x_1_14 = "Your data will be undecryptable" ascii //weight: 1
        $x_1_15 = "- Do not fool yourself. Encryption has perfect secrecy" ascii //weight: 1
        $x_2_16 = ".EncryptFiles." ascii //weight: 2
        $x_2_17 = ".EncryptFilename." ascii //weight: 2
        $x_2_18 = "D*struct { F uintptr; data *[]uint8; seed *uint8; fnc *main.decFunc }" ascii //weight: 2
        $x_1_19 = "golang.org/x/sys/windows.getSystemWindowsDirectory" ascii //weight: 1
        $x_1_20 = "path/filepath.WalkDir" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            ((1 of ($x_4_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win64_HiveCrypt_MF_2147832961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/HiveCrypt.MF!MTB"
        threat_id = "2147832961"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "HiveCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b7 44 08 04 35 5b 2e 00 00 40 80 f5 1a 40 0f b6 cd 88 8c 24 ee 05 00 00 48 c1 e1 30 48 c1 e0 20 48 09 c8 89 94 24 e8 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_HiveCrypt_SA_2147891807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/HiveCrypt.SA!MTB"
        threat_id = "2147891807"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "HiveCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 92 c2 c0 e2 ?? 08 ca 8a 8c 04 ?? ?? ?? ?? 8d 59 ?? 80 fb ?? 0f 92 c3 c0 e3 ?? 08 cb 48 ?? ?? 38 da 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_HiveCrypt_SU_2147893665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/HiveCrypt.SU!MTB"
        threat_id = "2147893665"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "HiveCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 0f 7e c0 ff c0 89 47 ?? 4d 01 ef 31 c0 8a 4c 05 ?? 41 30 0c 07 48 8d 48 ?? 48 89 c8 49 39 cc 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

