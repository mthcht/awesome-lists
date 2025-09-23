rule Trojan_Win32_MaleficAms_B_2147952862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MaleficAms.B"
        threat_id = "2147952862"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MaleficAms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "::FromBase64String($" wide //weight: 1
        $x_1_2 = ".CreateDecryptor()" wide //weight: 1
        $x_1_3 = ".WebClient" wide //weight: 1
        $x_1_4 = ".DownloadData($" wide //weight: 1
        $x_1_5 = ".GetString($" wide //weight: 1
        $x_1_6 = "ScriptBlock" wide //weight: 1
        $x_1_7 = "::Create(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

