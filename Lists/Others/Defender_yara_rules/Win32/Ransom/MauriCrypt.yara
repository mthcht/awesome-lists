rule Ransom_Win32_MauriCrypt_MK_2147785057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/MauriCrypt.MK!MTB"
        threat_id = "2147785057"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "MauriCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "github.com/mauri870/ransomware" ascii //weight: 10
        $x_5_2 = "main.encrypt0Files" ascii //weight: 5
        $x_10_3 = "Send0Encrypted0Payload" ascii //weight: 10
        $x_5_4 = "your device have been transferred to our server for storage" ascii //weight: 5
        $x_10_5 = "Desktop/ransomware/ransomware/cmd/common.go" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_MauriCrypt_MAK_2147786744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/MauriCrypt.MAK!MTB"
        threat_id = "2147786744"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "MauriCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Encrypting %s" ascii //weight: 1
        $x_1_2 = "$Recycle.Bin" ascii //weight: 1
        $x_1_3 = "FILES_ENCRYPTED.html" ascii //weight: 1
        $x_1_4 = "READ_TO_DECRYPT.html" ascii //weight: 1
        $x_1_5 = "-----END" ascii //weight: 1
        $x_1_6 = "-----BEGIN" ascii //weight: 1
        $x_1_7 = "master secret" ascii //weight: 1
        $x_1_8 = "key expansion" ascii //weight: 1
        $x_1_9 = "client finished" ascii //weight: 1
        $x_1_10 = "server finished" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

