rule Worm_Win32_Tifi_B_2147622968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Tifi.B!dr"
        threat_id = "2147622968"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Tifi"
        severity = "Critical"
        info = "dr: dropper component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shellexecute=Wscript.exe /e:vbs Dalifit.jpg" ascii //weight: 1
        $x_1_2 = "flashdrive.path &\"\\autorun.inf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

