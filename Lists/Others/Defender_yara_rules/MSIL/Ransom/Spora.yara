rule Ransom_MSIL_Spora_YBH_2147952049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Spora.YBH!MTB"
        threat_id = "2147952049"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spora"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AESxWin" ascii //weight: 1
        $x_1_2 = "ReadEncryptionHeader" ascii //weight: 1
        $x_1_3 = "get_Crypto" ascii //weight: 1
        $x_1_4 = "BwEncryptor_RunWorkerCompleted" ascii //weight: 1
        $x_1_5 = "BwEncryptor_DoWork" ascii //weight: 1
        $x_1_6 = "btnEncrypt_Click" ascii //weight: 1
        $x_1_7 = "btnDecrypt_Click" ascii //weight: 1
        $x_1_8 = "set_PasswordChar" ascii //weight: 1
        $x_1_9 = "DecryptFileAsync" ascii //weight: 1
        $x_1_10 = "RemoveExtension" ascii //weight: 1
        $x_1_11 = "ChangeExtension" ascii //weight: 1
        $x_1_12 = "AESxWin.AESxWinAuto+<GetPassword" ascii //weight: 1
        $x_1_13 = "AESxWin.AESxWinAuto+<GetIP" ascii //weight: 1
        $x_1_14 = "AESxWin.MainWindow+<btnEncrypt_Click" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

