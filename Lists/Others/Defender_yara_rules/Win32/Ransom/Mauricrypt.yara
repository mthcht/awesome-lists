rule Ransom_Win32_Mauricrypt_MX_2147962960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mauricrypt.MX!MTB"
        threat_id = "2147962960"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mauricrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VOS FICHIERS ONT ETE CHIFFRES" ascii //weight: 1
        $x_1_2 = "ENVOYER %s PAR TELEPATHIE" ascii //weight: 1
        $x_1_3 = "LE YOGA PEUT AIDER EN" ascii //weight: 1
        $x_1_4 = "github.com/mauri870/ransomware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

