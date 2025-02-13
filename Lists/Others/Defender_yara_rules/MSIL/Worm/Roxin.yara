rule Worm_MSIL_Roxin_A_2147656107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Roxin.A"
        threat_id = "2147656107"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Roxin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\\\.\\root\\SecurityCenter:AntivirusProduct" ascii //weight: 1
        $x_1_2 = "password" ascii //weight: 1
        $x_1_3 = "WormService" ascii //weight: 1
        $x_1_4 = "onAccessScanningEnabled" ascii //weight: 1
        $x_1_5 = "CMD.EXE /d /c echo open" ascii //weight: 1
        $x_1_6 = "&del *.*" ascii //weight: 1
        $x_1_7 = "soft.into4.info" ascii //weight: 1
        $x_1_8 = "/it.asp?intTimes=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Worm_MSIL_Roxin_B_2147656229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Roxin.B"
        threat_id = "2147656229"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Roxin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "Optical sensors monitor the atmosphere to detect the atmosphere of light and adjust the brightness of the display changes" wide //weight: 4
        $x_2_2 = "WakaSvc" wide //weight: 2
        $x_3_3 = "tcpz.sys" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_MSIL_Roxin_D_2147682695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Roxin.D"
        threat_id = "2147682695"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Roxin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 57 6f 72 6d 53 65 72 76 69 63 65 2e 65 78 65 00 3c 4d 6f 64 75 6c 65 3e 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 53 51 4c 53 65 72 76 65 72 41 74 74 61 63 6b 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 66 74 70 55 73 72 00 73 79 6e 55 73 72 00 66 74 70 50 73 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 53 71 6c 45 78 65 63 42 79 43 6d 64 53 68 65 6c 6c 00 63 6d 64 53 74 72 69 6e 67 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

