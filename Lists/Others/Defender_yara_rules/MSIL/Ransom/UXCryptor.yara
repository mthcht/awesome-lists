rule Ransom_MSIL_UXCryptor_SK_2147967856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/UXCryptor.SK!MTB"
        threat_id = "2147967856"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "UXCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%temp%\\$unlocker_id.ux-cryptobytes" ascii //weight: 1
        $x_1_2 = "echo [%RANDOM%] Ooops! Your files are encrypted by the UI-Load hacker group!" ascii //weight: 1
        $x_1_3 = "info-0v92.txt & attrib -h +s +r info-0v92.txt" ascii //weight: 1
        $x_1_4 = "%unlockkey%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

