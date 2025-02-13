rule Trojan_Win32_Thunmal_A_2147623503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Thunmal.A"
        threat_id = "2147623503"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Thunmal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "WoW.com Account/Password Retrieval" ascii //weight: 10
        $x_10_2 = "http://%s?u=%s&m=%s&action=find" ascii //weight: 10
        $x_10_3 = {63 3a 5c 70 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 54 68 75 6e 4d 61 69 6c 5c [0-8] 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_1_4 = "ZwDeviceIoControlFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

