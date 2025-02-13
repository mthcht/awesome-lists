rule TrojanDownloader_MSIL_Qhost_B_2147646279_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Qhost.B"
        threat_id = "2147646279"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2f 00 61 00 64 00 6d 00 69 00 6e 00 2f 00 69 00 6d 00 61 00 67 00 65 00 73 00 2f 00 66 00 6f 00 74 00 6f 00 73 00 2f 00 69 00 6d 00 61 00 [0-16] 2e 00 6a 00 70 00 67 00}  //weight: 2, accuracy: Low
        $x_2_2 = "System32\\drivers\\etc\\hosts" wide //weight: 2
        $x_2_3 = "\\system32\\drivers\\lsass.exe" wide //weight: 2
        $x_2_4 = ".youtube.com/watch?v=" wide //weight: 2
        $x_2_5 = "Windows Defender" wide //weight: 2
        $x_1_6 = "ConsentPromptBehaviorAdmin" wide //weight: 1
        $x_1_7 = "EnableInstallerDetection" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Qhost_E_2147647758_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Qhost.E"
        threat_id = "2147647758"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 00 21 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 44 00 65 00 66 00 65 00 6e 00 64 00 65 00 72}  //weight: 1, accuracy: High
        $x_1_2 = {75 72 6c 61 00 75 72 6c 62 00 75 72 6c 63 00 75 72 6c 64}  //weight: 1, accuracy: High
        $x_1_3 = {66 72 6d 41 64 6d 69 6e 69 73 74 72 61 44 65 73 63 61 72 67 61 00 41 64 6d 69 6e 69 73 74 72 61 44 65 73 63 61 72 67 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

