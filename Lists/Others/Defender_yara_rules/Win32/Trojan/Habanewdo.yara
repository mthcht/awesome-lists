rule Trojan_Win32_Habanewdo_2147955122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Habanewdo"
        threat_id = "2147955122"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Habanewdo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\CLDMSGPORT" wide //weight: 1
        $x_1_2 = "GLOBAL\\GLOBALROOT\\RPC Control" wide //weight: 1
        $x_1_3 = {ba a4 00 09 00 [0-16] ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = "CfRegisterSyncRoot" ascii //weight: 1
        $x_1_5 = "FilterSendMessage" ascii //weight: 1
        $x_1_6 = "FilterConnectCommunicationPort" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

