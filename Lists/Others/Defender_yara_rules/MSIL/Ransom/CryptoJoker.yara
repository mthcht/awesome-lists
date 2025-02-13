rule Ransom_MSIL_CryptoJoker_SN_2147768129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CryptoJoker.SN!MTB"
        threat_id = "2147768129"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptoJoker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EncryptFileFully" ascii //weight: 1
        $x_1_2 = "127.0.0.1) && (del /Q" wide //weight: 1
        $x_1_3 = "C:/Users/User/Desktop/MBR-Kill-master/MBR" wide //weight: 1
        $x_1_4 = "jokingwithyou.cryptojoker" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_CryptoJoker_PAA_2147782004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CryptoJoker.PAA!MTB"
        threat_id = "2147782004"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptoJoker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "my name is CryptoJoker !!" ascii //weight: 1
        $x_1_2 = "get_CryptoJokerMessage" ascii //weight: 1
        $x_1_3 = "I am ransomware" ascii //weight: 1
        $x_1_4 = "jok.crypt" ascii //weight: 1
        $x_1_5 = "SELECT * FROM Win32_OperatingSystem" wide //weight: 1
        $x_1_6 = "win32_logicaldisk.deviceid=\"" wide //weight: 1
        $x_1_7 = "\\encKey.crypt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_CryptoJoker_AYA_2147929771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CryptoJoker.AYA!MTB"
        threat_id = "2147929771"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptoJoker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "GonnaEncrypt.pdb" ascii //weight: 2
        $x_1_2 = "WannaEncrypt" wide //weight: 1
        $x_1_3 = "GonnaEncrypt_ProcessedByFody" ascii //weight: 1
        $x_1_4 = "Ransomware.Properties.Resources" wide //weight: 1
        $x_1_5 = "The file was encrypted" wide //weight: 1
        $x_1_6 = "howtodecrypt.html" wide //weight: 1
        $x_1_7 = "Sometimes suicide is bad... sometimes is good..." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

