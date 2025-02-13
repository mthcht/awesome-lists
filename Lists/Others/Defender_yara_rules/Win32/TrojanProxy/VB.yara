rule TrojanProxy_Win32_VB_N_2147608821_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/VB.N"
        threat_id = "2147608821"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "71"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "ReCS\\Server\\Services.vbp" wide //weight: 50
        $x_10_2 = "3932Services" ascii //weight: 10
        $x_10_3 = "69.46.18.49" wide //weight: 10
        $x_10_4 = "wskWebServerMain" ascii //weight: 10
        $x_1_5 = "capGetDriverDescriptionA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 3 of ($x_10_*))) or
            (all of ($x*))
        )
}

