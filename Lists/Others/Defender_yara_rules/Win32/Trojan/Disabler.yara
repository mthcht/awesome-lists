rule Trojan_Win32_Disabler_EH_2147843312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Disabler.EH!MTB"
        threat_id = "2147843312"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Disabler"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\TEMP\\8G11DVGA.cmd" ascii //weight: 1
        $x_1_2 = "ill /f /im \"AGMService.exe" ascii //weight: 1
        $x_1_3 = "taskkill /f" ascii //weight: 1
        $x_1_4 = "FindResourceW" ascii //weight: 1
        $x_1_5 = "DeleteFileW" ascii //weight: 1
        $x_1_6 = "CreateProcessW" ascii //weight: 1
        $x_1_7 = "CreateFileW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Disabler_GB_2147846992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Disabler.GB!MTB"
        threat_id = "2147846992"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Disabler"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 13 8b 7b 04 8b c2 8b 73 0c 33 c7 33 f7 89 43 04 8b c6 c1 e7 09 31 03 33 fa c1 c6 0b 68 a0 83 40 00 89 7b 08 89 73 0c ff 15}  //weight: 2, accuracy: High
        $x_2_2 = {6a 00 6a 00 6a 03 6a 00 6a 03 68 00 00 00 c0 68 8c 60 40 00 8b f8 ff 15}  //weight: 2, accuracy: High
        $x_1_3 = "This malware is no joke, continue?" wide //weight: 1
        $x_1_4 = "GOOD LUCK" wide //weight: 1
        $x_1_5 = "This malware requires NT 10.0 to run properly" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

