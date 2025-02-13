rule TrojanDownloader_Win32_Picproot_A_2147696245_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Picproot.A!dha"
        threat_id = "2147696245"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Picproot"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "HelpAssistant123456" ascii //weight: 1
        $x_1_2 = "Run_Install_HKCU!" ascii //weight: 1
        $x_1_3 = "Get Fun %s error!" ascii //weight: 1
        $x_1_4 = "Install Success!" ascii //weight: 1
        $x_1_5 = "%s /c attrib -h -r -s -a %s %s /c del %s /q" ascii //weight: 1
        $x_1_6 = "net localgroup administrators HelpAssistant /add" ascii //weight: 1
        $x_1_7 = {00 2e 32 34 2e 6a 70 67 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 2e 36 2e 6a 70 67 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 53 74 61 72 74 57 6f 72 6b 00}  //weight: 1, accuracy: High
        $x_1_10 = {00 43 72 65 64 65 6e 74 69 61 6c 73 2e 00}  //weight: 1, accuracy: High
        $x_1_11 = {00 45 48 41 47 42 50 53 4c 00}  //weight: 1, accuracy: High
        $x_1_12 = {00 4d 44 44 45 46 47 45 47 45 54 47 49 5a 00}  //weight: 1, accuracy: High
        $x_1_13 = "PH4.0 Q20" ascii //weight: 1
        $x_2_14 = {68 d0 07 00 00 ff 15 ?? ?? ?? 10 83 ff 02 75 22 56 ff 15 ?? ?? ?? 10 8b f8 68 30 75 00 00 ff 15 ?? ?? ?? 10 57 ff 15 ?? ?? ?? 10 56 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

