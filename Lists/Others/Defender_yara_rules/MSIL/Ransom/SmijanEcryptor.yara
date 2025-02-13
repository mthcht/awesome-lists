rule Ransom_MSIL_SmijanEcryptor_PAA_2147785417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/SmijanEcryptor.PAA!MTB"
        threat_id = "2147785417"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SmijanEcryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "39"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "unlock your files.lnk" ascii //weight: 10
        $x_10_2 = "bytesToBeEncrypted" ascii //weight: 10
        $x_10_3 = "Jasmin_Encrypter" ascii //weight: 10
        $x_10_4 = "Jasmin Encryptor" ascii //weight: 10
        $x_3_5 = "VolumeSerialNumber" wide //weight: 3
        $x_3_6 = "Win32_LogicalDisk" wide //weight: 3
        $x_3_7 = "handshake.php" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_3_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

