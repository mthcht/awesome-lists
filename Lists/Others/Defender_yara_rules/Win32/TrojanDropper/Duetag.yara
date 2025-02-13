rule TrojanDropper_Win32_Duetag_A_2147694149_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Duetag.A"
        threat_id = "2147694149"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Duetag"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://getp.jujutang.com" ascii //weight: 1
        $x_1_2 = "clisvc.exe" ascii //weight: 1
        $x_1_3 = "showdll" ascii //weight: 1
        $x_1_4 = {52 55 4e 44 41 54 41 00 25 73 5c 25 73 00}  //weight: 1, accuracy: High
        $x_1_5 = "\\MFrameWorks.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

