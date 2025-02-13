rule Trojan_Win32_AgeDown_DA_2147852019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AgeDown.DA!MTB"
        threat_id = "2147852019"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AgeDown"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%AppData%\\Dll" ascii //weight: 1
        $x_1_2 = "VScanPath=%%S" ascii //weight: 1
        $x_1_3 = "crackingcity" ascii //weight: 1
        $x_1_4 = {68 69 64 63 6f 6e 3a [0-7] 6d 61 69 6e 2e 62 61 74}  //weight: 1, accuracy: Low
        $x_1_5 = {68 69 64 63 6f 6e 3a [0-7] 56 53 2e 62 61 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

