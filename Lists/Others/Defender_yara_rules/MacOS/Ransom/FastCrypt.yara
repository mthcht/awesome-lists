rule Ransom_MacOS_FastCrypt_A_2147915884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MacOS/FastCrypt.A!MTB"
        threat_id = "2147915884"
        type = "Ransom"
        platform = "MacOS: "
        family = "FastCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.PasteRansomNote" ascii //weight: 1
        $x_1_2 = "FastCryptFiles" ascii //weight: 1
        $x_1_3 = "main.CryptAllDisk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

