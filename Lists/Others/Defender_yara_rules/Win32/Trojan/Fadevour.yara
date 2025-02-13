rule Trojan_Win32_Fadevour_LK_2147899302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fadevour.LK!MTB"
        threat_id = "2147899302"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fadevour"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 c0 d4 01 00 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {6a 36 6a 35 6a 34 6a 33 6a 32 6a 31 6a 30 6a 39 6a 38 6a 37 6a 36 6a 35 6a 34 6a 33 8b f0 6a 32 6a 31 8d 45 e4 6a 11}  //weight: 1, accuracy: High
        $x_1_3 = {6a 04 57 ff 76 50 ff 76 34 ff d3}  //weight: 1, accuracy: High
        $x_1_4 = {6a 04 68 00 10 00 00 ff 76 54 ff 75 fc ff d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

