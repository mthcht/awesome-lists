rule Ransom_Win64_Goransom_MKV_2147960527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Goransom.MKV!MTB"
        threat_id = "2147960527"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Goransom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qOqfwgtv2fSTz4BJb7wS/dYlaTqwli9SnI11Z8wAG/wZnAmV-Vac8y5g64VLeY/Ugl9h1oWkPPWMMyB7xye" ascii //weight: 1
        $x_1_2 = "encryptionKey" ascii //weight: 1
        $x_1_3 = "encryptedData" ascii //weight: 1
        $x_1_4 = "encryptedMPI1" ascii //weight: 1
        $x_1_5 = "encryptedMPI2" ascii //weight: 1
        $x_1_6 = "packet.EncryptedKey" ascii //weight: 1
        $x_1_7 = "packet.kdfAlgorithm" ascii //weight: 1
        $x_1_8 = "main.decodeString" ascii //weight: 1
        $x_1_9 = "main.decryptFile.func1" ascii //weight: 1
        $x_1_10 = "main.readmeFileName" ascii //weight: 1
        $x_1_11 = "main.encryptFileExt" ascii //weight: 1
        $x_1_12 = "CipherFunc" ascii //weight: 1
        $x_1_13 = "decodeHuffman" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Goransom_MKZ_2147960528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Goransom.MKZ!MTB"
        threat_id = "2147960528"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Goransom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nDe5-A0Ce3EyQzXKLdH3/Vqvl0V44lw-JT4d5IMyO/RWGt7lT4MhBmERi0HFax/sFJy09uiHXwDYsAMOaAm" ascii //weight: 1
        $x_5_2 = "cipher.cbcEncrypter" ascii //weight: 5
        $x_5_3 = "aes.encryptBlockGo" ascii //weight: 5
        $x_1_4 = "main.encryptFile" ascii //weight: 1
        $x_5_5 = "Goransom/encrypt.go" ascii //weight: 5
        $x_1_6 = "PrivateKey" ascii //weight: 1
        $x_1_7 = "as  at  fp= is  lr: of  on  pc" ascii //weight: 1
        $x_1_8 = "0330+0430+0530+0545+0630+0845+1030+1245+1345, ..., fp" ascii //weight: 1
        $x_1_9 = "-Inf.bat.cmd.com.css.exe.gif.htm.jpg.mjs.pdf.png" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

