rule Trojan_Win32_Angosay_A_2147725680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Angosay.A"
        threat_id = "2147725680"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Angosay"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {52 54 4d 5f 49 6d 61 67 65 4d 6f 64 52 65 63 2e 64 6c 6c [0-16] 52 48 42 69 6e 64 65 72 5f 5f 53 68 69 6d 45 78 65 4d 61 69 6e}  //weight: 20, accuracy: Low
        $x_10_2 = "Windows.UI.Xaml." ascii //weight: 10
        $x_1_3 = "ReadAllBytes" ascii //weight: 1
        $x_1_4 = "EncryptKey" ascii //weight: 1
        $x_1_5 = "WriteAllByte" ascii //weight: 1
        $x_1_6 = "get_FirstName" ascii //weight: 1
        $x_1_7 = "get_LastName" ascii //weight: 1
        $x_1_8 = "\\\"url\\\"\\s*:\\s*\\\"(http[" wide //weight: 1
        $x_1_9 = ":8080/getlogo" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 6 of ($x_1_*))) or
            ((1 of ($x_20_*))) or
            (all of ($x*))
        )
}

