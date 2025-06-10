rule Trojan_MSIL_InfoStealer_A_2147753778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/InfoStealer.A!MSR"
        threat_id = "2147753778"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "InfoStealer"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {42 24 4f f4 4f f4 4d d4 42 20 00 04 44 46 6f f6 64 46 6f}  //weight: 5, accuracy: High
        $x_5_2 = {46 67 75 56 63 36 6b b0 00 05 59 93 32}  //weight: 5, accuracy: High
        $x_5_3 = {48 65 48 65 00 44 61 79 6d 00 46 54 4f 4e 4a 00 63 6f 63 6f}  //weight: 5, accuracy: High
        $x_1_4 = "get_IsAttached" ascii //weight: 1
        $x_1_5 = "IsLogging" ascii //weight: 1
        $x_1_6 = "get_IsAlive" ascii //weight: 1
        $x_1_7 = "BlockCopy" ascii //weight: 1
        $x_1_8 = "fuck" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_InfoStealer_AB_2147756482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/InfoStealer.AB!MTB"
        threat_id = "2147756482"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ANTIVIRUS_CLASSNAME" ascii //weight: 1
        $x_1_2 = "USERNAME_TARGET_CREDENTIALS" ascii //weight: 1
        $x_1_3 = "GrabBrowserCredentials:" wide //weight: 1
        $x_1_4 = "ClientSettings.db" wide //weight: 1
        $x_1_5 = {41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 00 25 41 00 6e 00 74 00 69 00 53 00 70 00 79 00 57 00 61 00 72 00 65 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 00 1f 46 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 00 11 46 00 75 00 6c 00 6c 00 4e 00 61 00 6d 00 65 00 00 11 44 00 69 00 73 00 61 00 62 00 6c 00 65 00 64 00}  //weight: 1, accuracy: High
        $x_1_6 = "choice /C Y /N /D Y /T 3 & Del %2" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_InfoStealer_A_2147759674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/InfoStealer.A!MTB"
        threat_id = "2147759674"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 72 5d 01 00 70 6f ?? ?? ?? ?? 72 6d 01 00 70 6f ?? ?? ?? ?? 14 7e 03 00 00 04 6f ?? ?? ?? ?? 0b 09}  //weight: 1, accuracy: Low
        $x_10_2 = {54 6f 43 68 61 72 41 72 72 61 79 00 41 72 72 61 79 00 52 65 76 65 72 73 65 00 41 73 73 65 6d 62 6c 79 00 43 6f 6e 76 65 72 74 00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 00 4c 6f 61 64 00 47 65 74 54 79 70 65 00 47 65 74 4d 65 74 68 6f 64}  //weight: 10, accuracy: High
        $x_1_3 = "Data Source=.\\SQLEXPRESS;AttachDbFilenam" wide //weight: 1
        $x_1_4 = {2e 65 78 65 00 3c 4d 6f 64 75 6c 65 3e 00 2e 63 63 74 6f 72 00 58 41 58}  //weight: 1, accuracy: High
        $x_1_5 = "mobile-showroom-interiors-500x500" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_InfoStealer_ARA_2147836264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/InfoStealer.ARA!MTB"
        threat_id = "2147836264"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "AppDataGrabber" wide //weight: 2
        $x_2_2 = "CreditCardGrabber" wide //weight: 2
        $x_2_3 = "PasswordGrabber" wide //weight: 2
        $x_2_4 = "HistoryGrabber" wide //weight: 2
        $x_2_5 = "WalletGrabber" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_InfoStealer_ARA_2147836264_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/InfoStealer.ARA!MTB"
        threat_id = "2147836264"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MoveNext" ascii //weight: 1
        $x_1_2 = "System.Text" ascii //weight: 1
        $x_1_3 = "ReadAllText" ascii //weight: 1
        $x_1_4 = "ToArray" ascii //weight: 1
        $x_1_5 = "ToCharArray" ascii //weight: 1
        $x_1_6 = "ReadKey" ascii //weight: 1
        $x_1_7 = "System.Security.Cryptography" ascii //weight: 1
        $x_1_8 = "\\Google\\Chrome\\User Data" ascii //weight: 1
        $x_1_9 = "\\Default\\Login Data" ascii //weight: 1
        $x_1_10 = "\\Local State" ascii //weight: 1
        $x_1_11 = "encrypted_key" ascii //weight: 1
        $x_2_12 = "select * from logins" ascii //weight: 2
        $x_2_13 = "password_value" ascii //weight: 2
        $x_2_14 = "username_value" ascii //weight: 2
        $x_1_15 = "StringFileInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_InfoStealer_NITB_2147943275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/InfoStealer.NITB!MTB"
        threat_id = "2147943275"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 72 c1 0e 00 70 28 ?? 00 00 0a 0a 16 0b 2b 21 06 07 9a 0c 00 00 08 6f 62 00 00 0a 00 08 6f 37 00 00 0a 00 00 de 05 0d 00 00 de 00 00 07 17 58 0b 07 06 8e 69 32 d9}  //weight: 2, accuracy: Low
        $x_1_2 = "DownloadAndDecodeFileAsync" ascii //weight: 1
        $x_1_3 = "isOperaGXorFirefox" ascii //weight: 1
        $x_1_4 = "DecryptAndWriteFirefoxData" ascii //weight: 1
        $x_1_5 = "KillExistingTorProcesses" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

