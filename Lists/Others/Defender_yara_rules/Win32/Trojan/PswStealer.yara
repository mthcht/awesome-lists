rule Trojan_Win32_PswStealer_AA_2147751383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PswStealer.AA!MTB"
        threat_id = "2147751383"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PswStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PStealer_FileZilla" ascii //weight: 1
        $x_1_2 = "Stealer_TotalCmd" ascii //weight: 1
        $x_1_3 = "Server\\PasswordViewOnly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PswStealer_AA_2147751383_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PswStealer.AA!MTB"
        threat_id = "2147751383"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PswStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "discord.com/api/webhooks/" ascii //weight: 2
        $x_2_2 = "\"username\": \"Gr4bb\",\"content\": \"**TOKEN** :" ascii //weight: 2
        $x_2_3 = "CplusplusTest.pdb" ascii //weight: 2
        $x_1_4 = "Discord\\Local Storage\\leveldb" ascii //weight: 1
        $x_1_5 = "Lightcord\\Local Storage\\leveldb" ascii //weight: 1
        $x_1_6 = "Opera Software\\Opera Stable\\Local Storage\\leveldb" ascii //weight: 1
        $x_1_7 = "Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb" ascii //weight: 1
        $x_1_8 = "Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb" ascii //weight: 1
        $x_1_9 = "Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb" ascii //weight: 1
        $x_1_10 = "BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_PswStealer_A_2147827231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PswStealer.A"
        threat_id = "2147827231"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PswStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "110"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Select-String -Pattern pass*" wide //weight: 100
        $x_100_2 = "Select-String -Pattern passw*" wide //weight: 100
        $x_100_3 = "Select-String -Pattern password" wide //weight: 100
        $x_100_4 = "Select-String -Pattern psw*" wide //weight: 100
        $x_10_5 = "GetFolderPath" wide //weight: 10
        $x_10_6 = "System.Environment+SpecialFolder" wide //weight: 10
        $x_10_7 = "Desktop" wide //weight: 10
        $x_10_8 = "MyDocuments" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_PswStealer_B_2147827232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PswStealer.B"
        threat_id = "2147827232"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PswStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "111"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "pass*" wide //weight: 100
        $x_100_2 = "passw*" wide //weight: 100
        $x_100_3 = "password" wide //weight: 100
        $x_100_4 = "psw*" wide //weight: 100
        $x_10_5 = "Get-ChildItem" wide //weight: 10
        $x_1_6 = "System.Environment+SpecialFolder" wide //weight: 1
        $x_1_7 = "Desktop" wide //weight: 1
        $x_1_8 = "MyDocuments" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_PswStealer_C_2147827233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PswStealer.C"
        threat_id = "2147827233"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PswStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "210"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "cmd.exe" wide //weight: 100
        $x_100_2 = " pass" wide //weight: 100
        $x_100_3 = " psw" wide //weight: 100
        $x_10_4 = "copy" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 1 of ($x_10_*))) or
            ((3 of ($x_100_*))) or
            (all of ($x*))
        )
}

