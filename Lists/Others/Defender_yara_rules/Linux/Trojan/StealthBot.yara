rule Trojan_Linux_StealthBot_2147808232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/StealthBot"
        threat_id = "2147808232"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "StealthBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_16_1 = "StealthBot" ascii //weight: 16
        $x_4_2 = "UnableToCreateKerberosCredentials" ascii //weight: 4
        $x_4_3 = "MessageWasNotEncryptedWithTheRequiredEncryptingToken" ascii //weight: 4
        $x_4_4 = "CannotPerformS4UImpersonationOnPlatform" ascii //weight: 4
        $x_4_5 = "CreateDerivedKeyToken" ascii //weight: 4
        $x_4_6 = "UserNamePasswordValidationMode" ascii //weight: 4
        $x_4_7 = "ProvideImportExtensionsWithContextInformation" ascii //weight: 4
        $x_4_8 = "CreateDecryptor" ascii //weight: 4
        $x_4_9 = "CreateEncryptor" ascii //weight: 4
        $x_4_10 = "Populate83FileNameFromRandomBytes" ascii //weight: 4
        $x_2_11 = "Virtual " wide //weight: 2
        $x_2_12 = "ResourceA " wide //weight: 2
        $x_1_13 = "Process32First" ascii //weight: 1
        $x_1_14 = "Process32Next" ascii //weight: 1
        $x_1_15 = "ZwUnmapViewOfSection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((9 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((9 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_16_*) and 5 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_16_*) and 5 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_16_*) and 6 of ($x_4_*))) or
            (all of ($x*))
        )
}

