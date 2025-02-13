rule Ransom_MSIL_JigsawLocker_A_2147710637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/JigsawLocker.A"
        threat_id = "2147710637"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "JigsawLocker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Try anything funny and the computer has several safety measures to delete your files." wide //weight: 1
        $x_1_2 = "Within two minutes of receiving your payment your computer will receive the decryption key" wide //weight: 1
        $x_1_3 = "Every hour files will be deleted. Increasing in amount every time." wide //weight: 1
        $x_1_4 = "You are about to make a very bad decision. Are you sure about it" wide //weight: 1
        $x_1_5 = "After done I will close and completely remove myself from your computer." wide //weight: 1
        $x_1_6 = "You did not sent me enough! Try again!" wide //weight: 1
        $x_1_7 = "EncryptedFileList.txt" wide //weight: 1
        $x_1_8 = {52 61 6e 73 6f 6d 55 73 64 00}  //weight: 1, accuracy: High
        $x_1_9 = {42 6c 6f 63 6b 72 00}  //weight: 1, accuracy: High
        $x_1_10 = {67 65 74 5f 4a 69 67 73 61 77 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_MSIL_JigsawLocker_B_2147721602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/JigsawLocker.B"
        threat_id = "2147721602"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "JigsawLocker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".aaf .aep .aepx .plb" ascii //weight: 1
        $x_1_2 = ".3g2 .asf .asx .flv" ascii //weight: 1
        $x_1_3 = ".dbf .mdb .pdb .sql" ascii //weight: 1
        $x_1_4 = "GetBalanceBtc" ascii //weight: 1
        $x_1_5 = "I'm running in Debug mode" ascii //weight: 1
        $x_1_6 = "get_ExtensionsToEncrypt" ascii //weight: 1
        $x_1_7 = "get_vanityAddresses" ascii //weight: 1
        $x_1_8 = "<GetBitcoinAddess>" ascii //weight: 1
        $x_1_9 = "<EncryptFileSystem>" ascii //weight: 1
        $x_1_10 = "<EncryptFiles>" ascii //weight: 1
        $x_2_11 = {45 78 65 53 6d 61 72 74 43 6f 70 79 00 74 61 72 67 65 74 45 78 65 50 61 74 68 00 6f 76 65 72 77 72 69 74 65 00 53 68 6f 75 6c 64 41 63 74 69 76 61 74 65}  //weight: 2, accuracy: High
        $x_2_12 = {65 78 74 65 6e 73 69 6f 6e 73 54 6f 45 6e 63 72 79 70 74 00 44 65 63 72 79 70 74 46 69 6c 65 73 00 45 6e 63 72 79 70 74 46 69 6c 65}  //weight: 2, accuracy: High
        $x_1_13 = {00 52 61 6e 73 6f 6d 55 73 64 00}  //weight: 1, accuracy: High
        $x_1_14 = {00 42 6c 6f 63 6b 72 00}  //weight: 1, accuracy: High
        $x_2_15 = {00 67 65 74 5f 6b 44 46 51 37 4b 44 00}  //weight: 2, accuracy: High
        $x_1_16 = "Your computer files have been encryted." ascii //weight: 1
        $x_1_17 = "But, don't worry! they are not deleted yet." ascii //weight: 1
        $x_1_18 = "Great job, I'm decrypting your files..." ascii //weight: 1
        $x_1_19 = "your files will be deleted in 72 hours." ascii //weight: 1
        $x_1_20 = "EncryptedFileList.txt" ascii //weight: 1
        $x_1_21 = "NotTxtTest.nottxt" ascii //weight: 1
        $x_1_22 = "DeleteItself.bat" ascii //weight: 1
        $x_1_23 = "I am NOT a txt test." ascii //weight: 1
        $x_1_24 = "I am a txt test." ascii //weight: 1
        $x_1_25 = "You have to send $" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_JigsawLocker_C_2147733286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/JigsawLocker.C"
        threat_id = "2147733286"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "JigsawLocker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EncryptedFileList.txt" wide //weight: 1
        $x_1_2 = ".pennywiseA" wide //weight: 1
        $x_1_3 = "\\DeleteItself.bat" wide //weight: 1
        $x_1_4 = "NotTxtTest.nottxt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_MSIL_JigsawLocker_SBR_2147755534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/JigsawLocker.SBR!MSR"
        threat_id = "2147755534"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "JigsawLocker"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ransomware.Jigsaw\\obj\\x86\\Debug\\ConsoleApplication.pdb" ascii //weight: 1
        $x_1_2 = "ExtensionsToEncrypt" wide //weight: 1
        $x_1_3 = "WW91ciBwZXJzb25hbCBmaWxlcyBhcmUgYmVpbmcgZGVsZXRlZ" wide //weight: 1
        $x_1_4 = "ZW5jcnlwdGVkIHlvdXIgcGVyc29uYWwgZmlsZXM" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_JigsawLocker_DA_2147775310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/JigsawLocker.DA!MTB"
        threat_id = "2147775310"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "JigsawLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Your files have been encrypted" ascii //weight: 10
        $x_5_2 = "EncryptedFiles" ascii //weight: 5
        $x_4_3 = "BitcoinBlackmailer" ascii //weight: 4
        $x_3_4 = ".pornoransom" ascii //weight: 3
        $x_5_5 = "protonmail.com" ascii //weight: 5
        $x_4_6 = "BLOCKED" ascii //weight: 4
        $x_3_7 = "your own risk" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_3_*))) or
            ((1 of ($x_10_*) and 2 of ($x_4_*) and 2 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_4_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_JigsawLocker_DB_2147778639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/JigsawLocker.DB!MTB"
        threat_id = "2147778639"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "JigsawLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ExtensionsToEncrypt" ascii //weight: 1
        $x_1_2 = "I'm running in Debug mode" ascii //weight: 1
        $x_1_3 = "FormEncryptedFiles" ascii //weight: 1
        $x_1_4 = "cats" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_JigsawLocker_PA_2147779917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/JigsawLocker.PA!MTB"
        threat_id = "2147779917"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "JigsawLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "BitcoinStealer.exe" ascii //weight: 1
        $x_1_2 = {fe 0c 00 00 20 00 00 00 00 fe 0c 00 00 20 00 00 00 00 95 fe 0c 01 00 20 00 00 00 00 95 61 20 ?? ?? ?? ?? ?? 9e fe 0c 00 00 20 01 00 00 00 fe 0c 00 00 20 01 00 00 00 95 fe 0c 01 00 20 01 00 00 00 95 58 20 ?? ?? ?? ?? 61 9e fe 0c 00 00 20 02 00 00 00 fe 0c 00 00 20 02 00 00 00 95 fe 0c 01 00 20 02 00 00 00 95}  //weight: 1, accuracy: Low
        $x_1_3 = {fe 0c 08 00 fe 0c 0a 00 8f ?? 00 00 01 25 71 ?? 00 00 01 fe 0c 02 00 d2 61 d2 81 ?? 00 00 01 fe 0c 0a 00 20 ff 00 00 00 5f 3a 14 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_JigsawLocker_PB_2147781480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/JigsawLocker.PB!MTB"
        threat_id = "2147781480"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "JigsawLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BitcoinStealer.exe" ascii //weight: 1
        $x_1_2 = "Nitro PDF" wide //weight: 1
        $x_1_3 = "PrimoPDF.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

