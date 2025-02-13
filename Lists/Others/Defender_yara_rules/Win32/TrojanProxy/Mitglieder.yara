rule TrojanProxy_Win32_Mitglieder_A_2147573941_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Mitglieder.gen!A"
        threat_id = "2147573941"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Mitglieder"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "%s?p=%lu&id=%s&e=%lu" ascii //weight: 2
        $x_2_2 = "Key=1.2.3.4" ascii //weight: 2
        $x_2_3 = "ban_list.txt" ascii //weight: 2
        $x_2_4 = "if exist %1 goto l" ascii //weight: 2
        $x_2_5 = {75 69 64 00 70 6f 72 74}  //weight: 2, accuracy: High
        $x_1_6 = "HTTP/1.1 200 Connection" ascii //weight: 1
        $x_1_7 = "MaxIPConn" ascii //weight: 1
        $x_1_8 = {2d 75 70 64 00}  //weight: 1, accuracy: High
        $x_1_9 = {66 72 75 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

