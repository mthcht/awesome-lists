rule Trojan_Win32_Ramin_A_2147680286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ramin.A"
        threat_id = "2147680286"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ramin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "netsh firewall add allowedprogram \"%Windir%\\help\\svchost.exe\" \"Remote Administrator Server\" ENABLE" ascii //weight: 1
        $x_1_2 = "copy /y \"svchost.exe\" \"%SYSTEMROOT%/help\\svchost.exe\"" ascii //weight: 1
        $x_1_3 = "\"%SYSTEMROOT%/help\\svchost.exe\" /install /silence" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

