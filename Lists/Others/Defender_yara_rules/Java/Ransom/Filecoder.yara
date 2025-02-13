rule Ransom_Java_Filecoder_A_2147756282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Java/Filecoder.A!MTB"
        threat_id = "2147756282"
        type = "Ransom"
        platform = "Java: Java binaries (classes)"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "clicocryptor/Clicocryptor" ascii //weight: 1
        $x_1_2 = {68 74 74 70 3a 2f 2f [0-33] 2e 6f 6e 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_3 = "file_list_to_encrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Java_Filecoder_B_2147759072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Java/Filecoder.B!MTB"
        threat_id = "2147759072"
        type = "Ransom"
        platform = "Java: Java binaries (classes)"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tryencrpt" ascii //weight: 1
        $x_1_2 = "\\readmeonnotepad.javaencrypt" ascii //weight: 1
        $x_1_3 = "DESkey.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Java_Filecoder_C_2147759117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Java/Filecoder.C!MTB"
        threat_id = "2147759117"
        type = "Ransom"
        platform = "Java: Java binaries (classes)"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Scraper" ascii //weight: 1
        $x_1_2 = "PewCrypt" ascii //weight: 1
        $x_1_3 = "If T-Series beats Pewdiepie THE PRIVATE KEY WILL BE DELETED AND YOU FILES GONE FOREVER" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Java_Filecoder_D_2147810627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Java/Filecoder.D!MTB"
        threat_id = "2147810627"
        type = "Ransom"
        platform = "Java: Java binaries (classes)"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com/security/RansomProcess" ascii //weight: 2
        $x_1_2 = "StartEncryptProcess" ascii //weight: 1
        $x_2_3 = "CryptoRansomware" ascii //weight: 2
        $x_1_4 = "EncryptFile" ascii //weight: 1
        $x_1_5 = "removeCryptographyRestrictions" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Java_Filecoder_PA_2147810899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Java/Filecoder.PA!MTB"
        threat_id = "2147810899"
        type = "Ransom"
        platform = "Java: Java binaries (classes)"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CNo BITCOIN Sir , Your Files Are Toughly Encrypted" ascii //weight: 1
        $x_1_2 = "set_Ransomware_Configuration" ascii //weight: 1
        $x_1_3 = "Prepate_Key_For_Encryption" ascii //weight: 1
        $x_1_4 = ".Ransomkey" ascii //weight: 1
        $x_1_5 = "HackerData/RAT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Java_Filecoder_E_2147811029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Java/Filecoder.E!MTB"
        threat_id = "2147811029"
        type = "Ransom"
        platform = "Java: Java binaries (classes)"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "set_Ransomware_Configuration" ascii //weight: 1
        $x_1_2 = "Prepate_Key_For_Encryption" ascii //weight: 1
        $x_1_3 = ".Ransomkey" ascii //weight: 1
        $x_1_4 = "Main_Ransomware_Stub" ascii //weight: 1
        $x_1_5 = "hacker_data" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

