rule Trojan_Win32_Gofot_GPA_2147904588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gofot.GPA!MTB"
        threat_id = "2147904588"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gofot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "practicalmalwareanalysis.com/updater.exe" ascii //weight: 5
        $x_1_2 = {5c 77 69 6e 75 70 2e 65 78 65 00 00 25 73 25 73}  //weight: 1, accuracy: High
        $x_1_3 = {5c 73 79 73 74 65 6d 33 32 5c 77 75 70 64 6d 67 72 64 2e 65 78 65 00 00 25 73 25 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

