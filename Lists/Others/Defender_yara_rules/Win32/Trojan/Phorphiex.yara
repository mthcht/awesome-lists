rule Trojan_Win32_Phorphiex_ABPZ_2147967162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phorphiex.ABPZ!MTB"
        threat_id = "2147967162"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorphiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 74 74 70 3a 2f 2f 31 37 38 2e 31 36 2e 35 34 2e 31 30 39 2f [0-15] 2e 65 78 65}  //weight: 2, accuracy: Low
        $x_1_2 = "aaa_TouchMeNot_.txt" ascii //weight: 1
        $x_2_3 = "README.txt.scr" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

