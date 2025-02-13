rule Ransom_MSIL_ShinoLock_A_2147716967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/ShinoLock.A"
        threat_id = "2147716967"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShinoLock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 68 69 6e 6f 4c 6f 63 6b 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {53 68 69 6e 6f 4c 6f 63 6b 65 72 4d 61 69 6e 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = "ShinoLocker Server" ascii //weight: 1
        $x_1_4 = "Decrypt Files && Uninstall Me" ascii //weight: 1
        $x_1_5 = ".shino" ascii //weight: 1
        $x_1_6 = "Key is wrong!" ascii //weight: 1
        $x_1_7 = "ShinoLockerEncryptedFile" ascii //weight: 1
        $x_1_8 = {53 68 69 6e 6f 4c 6f 63 6b 65 72 4d 61 69 6e 2e 4d 79 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

