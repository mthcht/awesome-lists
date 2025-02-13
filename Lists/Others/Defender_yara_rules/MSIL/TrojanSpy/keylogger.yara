rule TrojanSpy_MSIL_keylogger_ABZ_2147833102_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/keylogger.ABZ!MTB"
        threat_id = "2147833102"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {07 07 6f 8c 00 00 0a 07 6f 8d 00 00 0a 6f 78 00 00 0a 0c 04 73 8e 00 00 0a 0d 09 08 16 73 8f 00 00 0a 13 04 11 04 06 16 06 8e 69 6f 92 00 00 0a 26 de 0c 11 04 2c 07 11 04 6f 24 00 00 0a dc}  //weight: 4, accuracy: High
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "TransformFinalBlock" ascii //weight: 1
        $x_1_4 = "TripleDESCryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

