rule Trojan_MacOS_Cabowato_A_2147741418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Cabowato.A"
        threat_id = "2147741418"
        type = "Trojan"
        platform = "MacOS: "
        family = "Cabowato"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "This file is corrupted and connot be opened" ascii //weight: 10
        $x_10_2 = ":pos or size error" ascii //weight: 10
        $x_10_3 = {3d 00 05 00 00 [0-6] 3d 00 08 00 00}  //weight: 10, accuracy: Low
        $x_10_4 = {3d ff 03 00 00 [0-6] 3d 00 03 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

