rule Ransom_Win64_Baphomet_DA_2147772564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Baphomet.DA!MTB"
        threat_id = "2147772564"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Baphomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Baphomet" ascii //weight: 1
        $x_1_2 = "get.php" ascii //weight: 1
        $x_1_3 = "yourkey.key" ascii //weight: 1
        $x_1_4 = "encryptFileData" ascii //weight: 1
        $x_1_5 = "Paste public rsa key here" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

