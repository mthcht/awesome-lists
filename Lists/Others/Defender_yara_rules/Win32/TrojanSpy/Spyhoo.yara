rule TrojanSpy_Win32_Spyhoo_A_2147609103_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Spyhoo.A"
        threat_id = "2147609103"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Spyhoo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "&from=SpyYahoo@yahoo.com&subject=Y.Password" wide //weight: 2
        $x_1_2 = "YahooBuddyMain" wide //weight: 1
        $x_1_3 = {41 00 75 00 74 00 68 00 6f 00 72 00 69 00 7a 00 65 00 64 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 73 00 5c 00 4c 00 69 00 73 00 74 00 00 00 00 00 1e 00 00 00 2e 00 65 00 78 00 65 00 3a 00 2a 00 3a 00 45 00 6e 00 61 00 62 00 6c 00 65 00 64 00 3a 00}  //weight: 1, accuracy: High
        $x_1_4 = "LookupAccountNameA" ascii //weight: 1
        $x_1_5 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

