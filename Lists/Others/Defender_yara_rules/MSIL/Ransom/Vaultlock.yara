rule Ransom_MSIL_Vaultlock_A_2147694096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Vaultlock.A"
        threat_id = "2147694096"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vaultlock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CoinVault" ascii //weight: 1
        $x_1_2 = "blacklistDirectories" ascii //weight: 1
        $x_1_3 = "excludePicturesFolder" ascii //weight: 1
        $x_1_4 = "KeysCollection" ascii //weight: 1
        $x_1_5 = "Files restored! Program will destroy itself." wide //weight: 1
        $x_1_6 = "CoinVaultFileList.txt" wide //weight: 1
        $x_1_7 = "Your worst nightmare." wide //weight: 1
        $x_1_8 = {66 72 6d 47 65 74 46 72 65 65 44 65 63 72 79 70 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

