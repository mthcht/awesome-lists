rule Trojan_Win32_DragonSpy_VC_2147759298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DragonSpy.VC!MTB"
        threat_id = "2147759298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DragonSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\Program Files\\svm\\svm.exe" ascii //weight: 1
        $x_1_2 = "process.txt" ascii //weight: 1
        $x_1_3 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 49 00 4d 00 20 00 [0-10] 2e 00 65 00 78 00 65 00 20 00 2f 00 46 00}  //weight: 1, accuracy: Low
        $x_1_4 = {74 61 73 6b 6b 69 6c 6c 20 2f 49 4d 20 [0-10] 2e 65 78 65 20 2f 46}  //weight: 1, accuracy: Low
        $x_1_5 = "www.ningzhidata.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

