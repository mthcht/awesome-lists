rule TrojanSpy_Win32_Iespy_H_2147592811_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Iespy.H"
        threat_id = "2147592811"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Iespy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SYSTEM\\CurrentControlSet\\Services\\BITS" ascii //weight: 10
        $x_10_2 = "%sSetup%d.exe" ascii //weight: 10
        $x_10_3 = "iloveyoufucktheworld" ascii //weight: 10
        $x_10_4 = {68 74 74 70 3a 2f 2f [0-32] 2f 64 6f 77 6e 2e 67 69 66}  //weight: 10, accuracy: Low
        $x_10_5 = {68 74 74 70 3a 2f 2f [0-32] 2f 63 68 65 63 6b 2e 61 73 70}  //weight: 10, accuracy: Low
        $x_4_6 = "bits.dll" wide //weight: 4
        $x_2_7 = "URLDownloadToFileA" ascii //weight: 2
        $x_2_8 = "ShellExecuteA" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*))) or
            (all of ($x*))
        )
}

