rule Ransom_Win32_JavaLocker_S_2147751475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/JavaLocker.S!MTB"
        threat_id = "2147751475"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "JavaLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".javalocker" ascii //weight: 1
        $x_1_2 = "\\readmeonnotepad.javaencrypt" ascii //weight: 1
        $x_1_3 = "What Happen to my computer?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

