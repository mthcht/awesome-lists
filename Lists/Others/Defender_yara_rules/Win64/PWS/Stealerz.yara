rule PWS_Win64_Stealerz_CM_2147963144_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win64/Stealerz.CM!MTB"
        threat_id = "2147963144"
        type = "PWS"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealerz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "sandbox check" ascii //weight: 2
        $x_2_2 = "Data Collection" ascii //weight: 2
        $x_2_3 = "Telegram:" ascii //weight: 2
        $x_2_4 = "Browsers:" ascii //weight: 2
        $x_2_5 = "Wallets:" ascii //weight: 2
        $x_2_6 = "Discord:" ascii //weight: 2
        $x_2_7 = "Clipboard:" ascii //weight: 2
        $x_2_8 = "\\system_info.txt" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

