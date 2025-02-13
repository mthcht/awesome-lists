rule TrojanDownloader_Java_GetShell_A_2147658602_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Java/GetShell.A"
        threat_id = "2147658602"
        type = "TrojanDownloader"
        platform = "Java: Java binaries (classes)"
        family = "GetShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "java/net/URL" ascii //weight: 5
        $x_5_2 = "java/lang/Runtime" ascii //weight: 5
        $x_5_3 = "java.io.tmpdir" ascii //weight: 5
        $x_5_4 = "chmod 755" ascii //weight: 5
        $x_5_5 = "CMD.exe /c start" ascii //weight: 5
        $x_5_6 = "Windows\\System32\\WindowsPowershell" ascii //weight: 5
        $x_10_7 = {12 b6 9b 2a 12 b6 3a 04 36 19 12 b6 99 12}  //weight: 10, accuracy: High
        $x_10_8 = {19 12 b6 9b 2a 12 b6 3a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 6 of ($x_5_*))) or
            ((2 of ($x_10_*) and 4 of ($x_5_*))) or
            (all of ($x*))
        )
}

