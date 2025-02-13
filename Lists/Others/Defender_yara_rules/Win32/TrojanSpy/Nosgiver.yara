rule TrojanSpy_Win32_Nosgiver_A_2147617883_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Nosgiver.A"
        threat_id = "2147617883"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Nosgiver"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\\\.\\KERNELDRIVER" ascii //weight: 1
        $x_1_2 = "#[[%s]]#" wide //weight: 1
        $x_1_3 = {42 39 c2 7c f4 89 1c 24 b8 ?? ?? 41 00 89 44 24 04 e8 ?? ?? 00 00 a3 ?? ?? 41 00 83 ec 08}  //weight: 1, accuracy: Low
        $x_1_4 = {6b 65 72 6e 65 6c 64 72 69 76 65 72 5c [0-32] 5c 50 47 50 73 63 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_5 = "%s\\system32\\wupdmgr.exe" wide //weight: 1
        $x_1_6 = "%s\\system32\\sigveri" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

