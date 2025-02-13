rule TrojanSpy_iPhoneOS_Ftikser_A_2147750358_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:iPhoneOS/Ftikser.A"
        threat_id = "2147750358"
        type = "TrojanSpy"
        platform = "iPhoneOS: "
        family = "Ftikser"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "fuck_iphone" ascii //weight: 1
        $x_1_2 = {78 73 73 65 72 2e 63 6f 6d [0-16] 38 30 [0-16] 25 40 3a 25 40 2f 43 68 65 63 6b 4c 69 62 72 61 72 79 2e 61 73 70 78}  //weight: 1, accuracy: Low
        $x_1_3 = {48 74 74 70 46 75 6e 4d 61 69 6e [0-16] 77 72 69 74 65 54 6f 46 69 6c 65 3a 61 74 6f 6d 69 63 61 6c 6c 79}  //weight: 1, accuracy: Low
        $x_1_4 = {2f 62 69 6e 2f 25 40 00 44 6f 77 6e 6c 6f 61 64 69 6e 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_iPhoneOS_Ftikser_A_2147750358_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:iPhoneOS/Ftikser.A"
        threat_id = "2147750358"
        type = "TrojanSpy"
        platform = "iPhoneOS: "
        family = "Ftikser"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "@:%@/TargetConnect.aspx?tpn=%@&tIMEI=%@&tIMSI=%@&tdv=%@&tov=%@&" ascii //weight: 1
        $x_1_2 = "%@:%@/TargetUploadGps.aspx?&tmac=%@&JZ=%@" ascii //weight: 1
        $x_1_3 = "Content-Disposition: form-data; " ascii //weight: 1
        $x_1_4 = {52 75 6e 43 6f 6d 6d 61 6e 64 3a [0-5] 53 65 6e 64 53 4d 53 3a [0-5] 43 61 6c 6c 54 65 6c 3a [0-5] 47 65 74 47 70 73 3a [0-5] 47 65 74 57 65 69 58 69 6e 3a [0-5] 47 65 74 4b 65 79 43 68 61 69 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

