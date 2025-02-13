rule Ransom_MSIL_Glock_A_2147688981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Glock.A"
        threat_id = "2147688981"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Glock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "9617c104-8052-4ded-ab6a-094f91c693d7" wide //weight: 1
        $x_1_2 = "CryptoLockerFileList.txt" wide //weight: 1
        $x_1_3 = "CLock" wide //weight: 1
        $x_10_4 = "Cryptographic Locker" wide //weight: 10
        $x_1_5 = "Check payment and receive keys" wide //weight: 1
        $x_1_6 = "Time untill costs raise" wide //weight: 1
        $x_2_7 = {7e 31 00 00 04 6f ?? 00 00 06 2d 02 16 2a 17 28 1b 00 00 0a 03 6f 01 00 00 06 28 1c 00 00 0a 2c 0d 03 6f 03 00 00 06 28 1c 00 00 0a 2c 02 16 2a 73 1d 00 00 0a 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

