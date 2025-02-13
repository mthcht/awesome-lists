rule Ransom_Linux_XdorCrypto_A_2147896286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/XdorCrypto.A!MTB"
        threat_id = "2147896286"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "XdorCrypto"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XdorCrypto" ascii //weight: 1
        $x_1_2 = "secureDeleteFile" ascii //weight: 1
        $x_1_3 = "encryptFile" ascii //weight: 1
        $x_1_4 = "checkExtension" ascii //weight: 1
        $x_1_5 = "writeFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

