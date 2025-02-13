rule Ransom_MSIL_MaikerCrypt_PAA_2147812392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/MaikerCrypt.PAA!MTB"
        threat_id = "2147812392"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MaikerCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".aes" wide //weight: 1
        $x_1_2 = "CryptMaiker" ascii //weight: 1
        $x_1_3 = "eqwczsewcxzqweqwe" wide //weight: 1
        $x_1_4 = "System.Windows.Markup" ascii //weight: 1
        $x_1_5 = "RNGCryptoServiceProvider" ascii //weight: 1
        $x_1_6 = "/NoName;component/mainwindow.xaml" wide //weight: 1
        $x_1_7 = "NoName\\NoName\\obj\\Debug\\NoName.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

