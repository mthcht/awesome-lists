rule Ransom_Win32_Finicrypt_A_2147707693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Finicrypt.A"
        threat_id = "2147707693"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Finicrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "have been encrypted using a military grade encryption algorithm." ascii //weight: 1
        $x_1_2 = "After 24h have passed, your decryption key will be erased and" ascii //weight: 1
        $x_1_3 = "/k vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 1
        $x_1_4 = "\\ReadDecryptFilesHere.txt" ascii //weight: 1
        $x_1_5 = "Software\\CryptInfinite" ascii //weight: 1
        $x_1_6 = ".onion.direct/lending/bot.php?name=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

