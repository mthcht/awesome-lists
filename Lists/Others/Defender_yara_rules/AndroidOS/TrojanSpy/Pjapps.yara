rule TrojanSpy_AndroidOS_Pjapps_A_2147643748_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Pjapps.A"
        threat_id = "2147643748"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Pjapps"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3a 39 30 33 33 2f [0-7] 2e 6c 6f 67 3f 69 64 3d}  //weight: 1, accuracy: Low
        $x_1_2 = {3a 38 31 31 38 2f 70 75 73 68 2f [0-3] 61 6e 64 72 6f 69 64 78 6d 6c 2f}  //weight: 1, accuracy: Low
        $x_1_3 = {26 73 6f 66 74 69 64 3d [0-2] 26 63 6e 3d [0-2] 26 6e 74 3d}  //weight: 1, accuracy: Low
        $x_1_4 = "/mm.do?imei=" ascii //weight: 1
        $x_1_5 = "http://xxxxxxxxx9:8618/client/android/a.apk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

