rule Ransom_MSIL_ApisCryptor_PAA_2147783929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/ApisCryptor.PAA!MTB"
        threat_id = "2147783929"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ApisCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "65"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "checkdisableRecoveryMode" ascii //weight: 10
        $x_10_2 = "checkdeleteShadowCopies" ascii //weight: 10
        $x_10_3 = "encryptedFileExtension" ascii //weight: 10
        $x_10_4 = "<EncyptedKey>" wide //weight: 10
        $x_10_5 = "infected with a ransomware virus." wide //weight: 10
        $x_10_6 = "read_apis.txt" wide //weight: 10
        $x_5_7 = "vssadmin delete shadows /all /quiet & wmic shadowcopy delete" wide //weight: 5
        $x_5_8 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no" wide //weight: 5
        $x_5_9 = "wbadmin delete catalog -quiet" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 3 of ($x_5_*))) or
            ((6 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

