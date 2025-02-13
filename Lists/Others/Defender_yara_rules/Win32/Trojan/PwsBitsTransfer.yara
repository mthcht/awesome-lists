rule Trojan_Win32_PwsBitsTransfer_A_2147903967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PwsBitsTransfer.A"
        threat_id = "2147903967"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PwsBitsTransfer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -nop -c" ascii //weight: 1
        $x_1_2 = "start-job {" ascii //weight: 1
        $x_1_3 = "Import-Module BitsTransfer" ascii //weight: 1
        $x_1_4 = "Start-BitsTransfer -Source " ascii //weight: 1
        $x_1_5 = "IEX $" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

