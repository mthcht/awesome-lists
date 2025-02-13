rule Trojan_Win32_Phobos_MA_2147840701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phobos.MA!MTB"
        threat_id = "2147840701"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phobos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {84 a4 55 c2 82 e6 a7 79 26 b2 a5 f7 43 03 f9 eb b5 41 21 8d 35 78 4b 25 81 a9 6e 1e 07 57 55 6b 48 d8 6b 99 20 8b f8 c8 75 d6 65 cd 19 62 20 d3}  //weight: 5, accuracy: High
        $x_5_2 = {cb a6 7b c2 e7 e6 df 79 ee bf 9f f7 70 03 cb eb f7 dd a6 1a 5e 17 a4 15 ab 2c b9 8f c8 58 29 cf}  //weight: 5, accuracy: High
        $x_1_3 = "RegisterWaitForSingleObject" ascii //weight: 1
        $x_1_4 = "InitCommonControlsEx" ascii //weight: 1
        $x_1_5 = "PostMessageW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

