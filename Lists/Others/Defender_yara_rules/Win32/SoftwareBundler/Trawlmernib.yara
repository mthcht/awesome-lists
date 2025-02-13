rule SoftwareBundler_Win32_Trawlmernib_222303_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Trawlmernib"
        threat_id = "222303"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Trawlmernib"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".?AVRamblerPage@@" ascii //weight: 1
        $x_1_2 = {52 00 55 00 70 00 64 00 61 00 74 00 65 00 5f 00 25 00 73 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "dl.zvu.com/pinstall/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule SoftwareBundler_Win32_Trawlmernib_222303_1
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Trawlmernib"
        threat_id = "222303"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Trawlmernib"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set Rambler search by default" ascii //weight: 1
        $x_1_2 = {26 00 70 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 3d 00 25 00 73 00 26 00 70 00 65 00 78 00 69 00 74 00 63 00 6f 00 64 00 65 00 3d 00 25 00 73 00 26 00 70 00 72 00 65 00 73 00 75 00 6c 00 74 00 3d 00 25 00 73 00 26 00 63 00 61 00 6d 00 70 00 61 00 69 00 67 00 6e 00 5f 00 69 00 64 00 3d 00 25 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "vkmusic.ru/VKMUSICsetup.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule SoftwareBundler_Win32_Trawlmernib_222303_2
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Trawlmernib"
        threat_id = "222303"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Trawlmernib"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {53 65 74 20 52 61 6d 62 6c 65 72 20 73 65 61 72 63 68 20 62 79 20 64 65 66 61 75 6c 74 00}  //weight: 10, accuracy: High
        $x_10_2 = {64 00 6c 00 2e 00 6d 00 69 00 6e 00 69 00 6c 00 6f 00 61 00 64 00 2e 00 6f 00 72 00 67 00 2f 00 70 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2f 00 52 00 55 00 70 00 64 00 61 00 74 00 65 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 10, accuracy: High
        $x_1_3 = "pinstall=\"rambler\" pparams" ascii //weight: 1
        $x_1_4 = "pinstall=rambler&campaign_id=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

