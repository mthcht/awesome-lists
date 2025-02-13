rule Ransom_Win64_WhiteBlackCrypt_PA_2147779023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/WhiteBlackCrypt.PA!MTB"
        threat_id = "2147779023"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "WhiteBlackCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = ".encrpt3d" ascii //weight: 3
        $x_2_2 = "C:\\ProgramData\\CheckServiceD.exe" ascii //weight: 2
        $x_2_3 = "Your files has been ENCRYPTED!" ascii //weight: 2
        $x_1_4 = "Whiteblackgroup002@gmail.com" ascii //weight: 1
        $x_1_5 = "Wbgroup022@gmail.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

