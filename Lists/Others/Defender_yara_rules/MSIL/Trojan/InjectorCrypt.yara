rule Trojan_MSIL_InjectorCrypt_A_2147762586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/InjectorCrypt.A!MTB"
        threat_id = "2147762586"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "InjectorCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "explorer_enc" wide //weight: 1
        $x_1_2 = "RC4decrypt" ascii //weight: 1
        $x_1_3 = "RC2Decrypt" ascii //weight: 1
        $x_1_4 = "EntryPoint" wide //weight: 1
        $x_1_5 = "explorer.exe" ascii //weight: 1
        $x_1_6 = "explorer.Resources" ascii //weight: 1
        $x_1_7 = {5a 49 50 20 52 43 32 20 52 43 34 5c 64 65 63 6f 64 65 5c [0-48] 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 65 78 70 6c 6f 72 65 72 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_MSIL_InjectorCrypt_SR_2147775691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/InjectorCrypt.SR!MTB"
        threat_id = "2147775691"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "InjectorCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 07 02 8e 69 6a 5d 28 [0-9] 91 06 07 06 8e 69 6a 5d 28 [0-9] 91 61 02 07 17 6a 58 02 8e 69 6a 5d 28 [0-9] 91 59 6a 20 [0-4] 6a 58 20 [0-4] 6a 5d d2 9c 00 07 17 6a 58 0b}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

