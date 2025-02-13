rule Trojan_Win32_Sparrot_A_2147817177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sparrot.A!dha"
        threat_id = "2147817177"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sparrot"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "The buffer length isnot enought!" ascii //weight: 1
        $x_1_2 = "Malloc Error" ascii //weight: 1
        $x_1_3 = "Open OR Write File Error" ascii //weight: 1
        $x_1_4 = "/upload.php" ascii //weight: 1
        $x_1_5 = "Content-Disposition: form-data; name=\"file\"; filename=" ascii //weight: 1
        $x_1_6 = "SparrowDll.dll" ascii //weight: 1
        $x_1_7 = "MyAgent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

