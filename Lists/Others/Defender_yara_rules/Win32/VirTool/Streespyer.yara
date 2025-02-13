rule VirTool_Win32_Streespyer_A_2147628877_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Streespyer.A"
        threat_id = "2147628877"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Streespyer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "TFM_S3C_KL_MENS" wide //weight: 10
        $x_10_2 = "C:\\s3c_Sistemas\\Spia" ascii //weight: 10
        $x_10_3 = "explorer.exe /e, /select," ascii //weight: 10
        $x_1_4 = "TFM_S3C_SK22_LOGIN" wide //weight: 1
        $x_1_5 = "TFM_S3C_K14_LOGIN" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

