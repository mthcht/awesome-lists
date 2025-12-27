rule Ransom_PowerShell_WarLock_B_2147950819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:PowerShell/WarLock.B"
        threat_id = "2147950819"
        type = "Ransom"
        platform = "PowerShell: "
        family = "WarLock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-Recurse -Include *.pdf,*.txt, *.doc" wide //weight: 1
        $x_1_2 = "\".xlockxlock\"" wide //weight: 1
        $x_1_3 = "$aes.CreateEncryptor($aes.Key, $aes.IV);" wide //weight: 1
        $x_1_4 = "Get-Random -Maximum 74" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

