rule Ransom_Win32_RapidCrypt_PA_2147808525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/RapidCrypt.PA!MTB"
        threat_id = "2147808525"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "RapidCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".rapid" ascii //weight: 1
        $x_1_2 = "Software\\EncryptKeys" ascii //weight: 1
        $x_1_3 = "All your files have been ENCRYPTED" ascii //weight: 1
        $x_1_4 = "How Recovery Files.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

