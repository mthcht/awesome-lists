rule Ransom_Win32_BlueLocker_MK_2147805854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BlueLocker.MK!MTB"
        threat_id = "2147805854"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BlueLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$Recycle.Bin" ascii //weight: 1
        $x_1_2 = "restore_file.txt" ascii //weight: 1
        $x_1_3 = "Your computers and servers are encrypted" ascii //weight: 1
        $x_1_4 = "/C wmic SHADOWCOPY DELETE" ascii //weight: 1
        $x_1_5 = "!!! DANGER !!" ascii //weight: 1
        $x_1_6 = "DO NOT MODIFY or try to RECOVER any files yourself" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

