rule Ransom_Win32_TimeCrypt_MAK_2147809530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/TimeCrypt.MAK!MTB"
        threat_id = "2147809530"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "TimeCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Time Ransomware" ascii //weight: 1
        $x_2_2 = "All of your documents,musics,videos have been encrypted" ascii //weight: 2
        $x_2_3 = "To recover your data, you need to pay us" ascii //weight: 2
        $x_2_4 = "we will leak everything on the dark web" ascii //weight: 2
        $x_2_5 = "do not rename encrypted files" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

