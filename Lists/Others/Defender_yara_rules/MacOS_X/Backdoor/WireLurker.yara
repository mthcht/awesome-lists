rule Backdoor_MacOS_X_WireLurker_A_2147706417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS_X/WireLurker.A"
        threat_id = "2147706417"
        type = "Backdoor"
        platform = "MacOS_X: "
        family = "WireLurker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 6f 6d 65 69 6e 62 61 62 79 2e 63 6f 6d 2f 61 70 70 2f 61 70 70 2e 70 68 70 3f 73 6e 3d 25 73 26 70 6e 3d 25 73 26 6d 6e 3d 25 73 26 70 76 3d 25 73 26 61 70 70 69 64 3d 25 73 26 6f 73 3d 6d 61 63 73 65 72 76 69 63 65 26 70 74 3d 25 73 26 6d 73 6e 3d 25 40 26 79 79 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {2f 6d 61 63 2f 73 61 76 65 69 6e 66 6f 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_3 = "Could not start com.apple.mobile.installation_proxy!" ascii //weight: 1
        $x_1_4 = {2f 75 73 72 2f 6c 6f 63 61 6c 2f 6d 61 63 68 6f 6f 6b 2f 77 61 74 63 68 2e 73 68 00}  //weight: 1, accuracy: High
        $x_1_5 = {2f 74 6d 70 2f 6d 61 63 68 6f 6f 6b 2e 6c 6f 67 00}  //weight: 1, accuracy: High
        $x_1_6 = {2f 6f 70 74 2f 63 6f 64 65 2f 61 70 70 2f 6d 79 50 72 6f 6a 65 63 74 2f 6d 61 63 68 6f 6f 6b 2f 6d 61 63 68 6f 6f 6b 2f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

