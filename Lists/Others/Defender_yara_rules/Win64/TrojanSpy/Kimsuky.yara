rule TrojanSpy_Win64_Kimsuky_AR_2147960254_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win64/Kimsuky.AR!AMTB"
        threat_id = "2147960254"
        type = "TrojanSpy"
        platform = "Win64: Windows 64-bit platform"
        family = "Kimsuky"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "C:\\Documents and Settings\\JohnDoe\\Local Settings\\Application Data\\nzvwan.log" ascii //weight: 5
        $x_5_2 = "%s\\nzvwan.log" ascii //weight: 5
        $x_5_3 = "baby.dll" ascii //weight: 5
        $x_5_4 = "chrome.exe" ascii //weight: 5
        $x_2_5 = "ReflectiveLoader" ascii //weight: 2
        $x_2_6 = "CreateRemoteThread" ascii //weight: 2
        $x_2_7 = "CreateFileW" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

