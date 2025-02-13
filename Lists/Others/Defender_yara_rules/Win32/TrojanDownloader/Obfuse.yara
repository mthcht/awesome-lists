rule TrojanDownloader_Win32_Obfuse_GA_2147761918_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Obfuse.GA!MSR"
        threat_id = "2147761918"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuse"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b c1 80 f3 78 99 f7 7c 24 20 8a 04 2a 8a 14 31 32 d0 88 14 31 41 3b cf}  //weight: 2, accuracy: High
        $x_1_2 = "chxsaprfywn" ascii //weight: 1
        $x_1_3 = "History of Tibet-Ladakh Relations and Their Modern Implications.docx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

