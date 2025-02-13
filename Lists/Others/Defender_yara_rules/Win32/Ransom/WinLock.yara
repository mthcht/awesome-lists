rule Ransom_Win32_WinLock_RDA_2147901839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/WinLock.RDA!MTB"
        threat_id = "2147901839"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "WinLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Trashing the system..." ascii //weight: 1
        $x_1_2 = "if u see this then ur system is dead" ascii //weight: 1
        $x_1_3 = "hildaboo, if you see this" ascii //weight: 1
        $x_1_4 = ", im sorry." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

