rule Ransom_Win32_LockFile_MK_2147789394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockFile.MK!MTB"
        threat_id = "2147789394"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockFile"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EncodingParameters" ascii //weight: 1
        $x_1_2 = "LOCKFILE" ascii //weight: 1
        $x_1_3 = "<computername>%s</computername>" ascii //weight: 1
        $x_1_4 = "<blocknum>%d</blocknum>" ascii //weight: 1
        $x_1_5 = "winsta0\\default" ascii //weight: 1
        $x_1_6 = "cmd.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

