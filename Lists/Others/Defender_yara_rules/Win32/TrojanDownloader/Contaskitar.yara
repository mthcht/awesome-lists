rule TrojanDownloader_Win32_Contaskitar_A_2147697665_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Contaskitar.A"
        threat_id = "2147697665"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Contaskitar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {2e 73 6b 69 70 70 65 64 69 61 2e 6e 65 74 2f [0-4] 30 32 31 34 64 2f 73 74 61 72 74 32 6d 65 2e 65 78 65}  //weight: 8, accuracy: Low
        $x_2_2 = "goo.gl/z3wkmI" wide //weight: 2
        $x_2_3 = "goo.gl/HzjJkR" wide //weight: 2
        $x_2_4 = "goo.gl/Y3udQ6" wide //weight: 2
        $x_2_5 = "goo.gl/NMQvA" wide //weight: 2
        $x_2_6 = "goo.gl/WQoFD" wide //weight: 2
        $x_1_7 = "URL=http://www.contaprime.com/?desktop" ascii //weight: 1
        $x_1_8 = "CONTAPRIME DOWNLOADS.url" ascii //weight: 1
        $x_1_9 = {77 77 77 2e 73 6b 69 70 70 65 64 69 61 2e 6e 65 74 2f 31 ?? 30 32 31 34 64 2f 31 ?? 30 32 31 34 5f [0-4] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_10 = "/PARTNER=pcdealplypm /CHANNEL=pcdealplypm" ascii //weight: 1
        $x_1_11 = "-affilid=127457" ascii //weight: 1
        $x_1_12 = "-affilid=128392" ascii //weight: 1
        $x_1_13 = "/cid=117 /hash=fouuf6" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_8_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_8_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_8_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_8_*) and 5 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Contaskitar_B_2147697670_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Contaskitar.B"
        threat_id = "2147697670"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Contaskitar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "goo.gl/NMQvA" ascii //weight: 4
        $x_4_2 = "goo.gl/WQoFD" ascii //weight: 4
        $x_4_3 = "goo.gl/Y6fLFj" ascii //weight: 4
        $x_2_4 = "-affilid=127402" ascii //weight: 2
        $x_1_5 = "SOFTWARE\\nationzoomSoftware" ascii //weight: 1
        $x_1_6 = "6432Node\\BeatTool" ascii //weight: 1
        $x_1_7 = "/aflt=pc0102 /instlRef=pc0102 /rvt /prod:def" ascii //weight: 1
        $x_1_8 = "Uninstall\\avast" ascii //weight: 1
        $x_1_9 = "4AA46D49-459F-4358-B4D1-169048547C23" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_4_*) and 4 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

