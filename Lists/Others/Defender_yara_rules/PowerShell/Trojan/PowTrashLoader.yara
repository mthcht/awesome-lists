rule Trojan_PowerShell_PowTrashLoader_SA_2147897575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/PowTrashLoader.SA"
        threat_id = "2147897575"
        type = "Trojan"
        platform = "PowerShell: "
        family = "PowTrashLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "system.security.cryptography.aesmanaged" wide //weight: 1
        $x_1_3 = ".keysize" wide //weight: 1
        $x_1_4 = "::ecb" wide //weight: 1
        $x_1_5 = "frombase64string" wide //weight: 1
        $x_1_6 = ".createdecryptor" wide //weight: 1
        $x_1_7 = "transformfinalblock" wide //weight: 1
        $x_1_8 = ".gzipstream" wide //weight: 1
        $x_1_9 = "::decompress" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

