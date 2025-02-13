rule PWS_MSIL_HawkEye_GG_2147777408_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/HawkEye.GG!MTB"
        threat_id = "2147777408"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HawkEye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {48 00 61 00 77 00 6b 00 45 00 79 00 65 00 [0-4] 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00}  //weight: 20, accuracy: Low
        $x_20_2 = {48 61 77 6b 45 79 65 [0-4] 4b 65 79 6c 6f 67 67 65 72}  //weight: 20, accuracy: Low
        $x_1_3 = "Dear HawkEye" ascii //weight: 1
        $x_1_4 = {43 00 6c 00 69 00 70 00 42 00 6f 00 61 00 72 00 64 00 [0-6] 52 00 65 00 63 00 6f 00 72 00 64 00}  //weight: 1, accuracy: Low
        $x_1_5 = {43 6c 69 70 42 6f 61 72 64 [0-6] 52 65 63 6f 72 64}  //weight: 1, accuracy: Low
        $x_1_6 = {4b 00 65 00 79 00 6c 00 6f 00 67 00 [0-6] 52 00 65 00 63 00 6f 00 72 00 64 00}  //weight: 1, accuracy: Low
        $x_1_7 = {4b 65 79 6c 6f 67 [0-6] 52 65 63 6f 72 64}  //weight: 1, accuracy: Low
        $x_1_8 = "screenshot" ascii //weight: 1
        $x_1_9 = "Stealer" ascii //weight: 1
        $x_1_10 = "Wallet" ascii //weight: 1
        $x_1_11 = "bitcoin}" ascii //weight: 1
        $x_1_12 = "Disablespreader" ascii //weight: 1
        $x_1_13 = "WebBrowserPassView" ascii //weight: 1
        $x_1_14 = "Bank" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 6 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

