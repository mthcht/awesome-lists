rule Trojan_Win64_MuggleStealer_DA_2147850509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MuggleStealer.DA!MTB"
        threat_id = "2147850509"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MuggleStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "github.com/phil-fly/generate" ascii //weight: 1
        $x_1_2 = "Go build ID:" ascii //weight: 1
        $x_1_3 = "screenshot.png" ascii //weight: 1
        $x_1_4 = "ChromePwd" ascii //weight: 1
        $x_1_5 = "Login Data" ascii //weight: 1
        $x_1_6 = "Wincreds" ascii //weight: 1
        $x_1_7 = "UploadFile" ascii //weight: 1
        $x_1_8 = "DiskInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

