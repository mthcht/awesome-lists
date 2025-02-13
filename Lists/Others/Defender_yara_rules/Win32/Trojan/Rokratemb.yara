rule Trojan_Win32_Rokratemb_A_2147730347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rokratemb.A"
        threat_id = "2147730347"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rokratemb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "base64Encoded=\"TVqQAAMAAAAEAAAA" ascii //weight: 1
        $x_1_2 = "outFile=sysDir&\"\\rundll32.exe\"" ascii //weight: 1
        $x_1_3 = "writeBytes outFile, base64Decoded" ascii //weight: 1
        $x_1_4 = "command =outFile &\" sysupdate\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

