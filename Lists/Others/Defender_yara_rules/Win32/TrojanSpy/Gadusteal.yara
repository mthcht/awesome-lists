rule TrojanSpy_Win32_Gadusteal_2147627592_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Gadusteal"
        threat_id = "2147627592"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Gadusteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Dane aplikacji\\Nowe Gadu-Gadu\\" ascii //weight: 1
        $x_1_2 = {71 77 65 72 74 79 00 31 32 37 78 2e 79 6f 79 6f 2e 70 6c}  //weight: 1, accuracy: High
        $x_1_3 = "Archive.db" ascii //weight: 1
        $x_1_4 = "Profile.xml" ascii //weight: 1
        $x_1_5 = "ProfileBasic.xml" ascii //weight: 1
        $x_1_6 = "ContactList.xml" ascii //weight: 1
        $x_1_7 = "FtpPutFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

